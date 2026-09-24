// Copyright 2020 The Prometheus Authors
// This code is partly borrowed from Caddy:
//    Copyright 2015 Matthew Holt and The Caddy Authors
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package web

import (
	"encoding/hex"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"sync"

	config_util "github.com/prometheus/common/config"
	"golang.org/x/crypto/bcrypt"
	"golang.org/x/time/rate"
)

// decoyPassword is hashed to produce the hash that requests for unknown users
// are compared against. Its value is irrelevant; only the cost of hashing it
// matters.
const decoyPassword = "fakepassword"

// extraHTTPHeaders is a map of HTTP headers that can be added to HTTP
// responses.
// This is private on purpose to ensure consistency in the Prometheus ecosystem.
var extraHTTPHeaders = map[string][]string{
	"Strict-Transport-Security": nil,
	"X-Content-Type-Options":    {"nosniff"},
	"X-Frame-Options":           {"deny", "sameorigin"},
	"X-XSS-Protection":          nil,
	"Content-Security-Policy":   nil,
}

func validateUsers(configPath string) error {
	c, err := getConfig(configPath)
	if err != nil {
		return err
	}

	for _, p := range c.Users {
		_, err = bcrypt.Cost([]byte(p))
		if err != nil {
			return err
		}
	}

	return nil
}

// validateHeaderConfig checks that the provided header configuration is correct.
// It does not check the validity of all the values, only the ones which are
// well-defined enumerations.
func validateHeaderConfig(headers map[string]string) error {
HeadersLoop:
	for k, v := range headers {
		values, ok := extraHTTPHeaders[k]
		if !ok {
			return fmt.Errorf("HTTP header %q can not be configured", k)
		}
		for _, allowedValue := range values {
			if v == allowedValue {
				continue HeadersLoop
			}
		}
		if len(values) > 0 {
			return fmt.Errorf("invalid value for %s. Expected one of: %q, but got: %q", k, values, v)
		}
	}
	return nil
}

// maxBcryptCost returns the highest bcrypt cost among the configured users, or
// bcrypt.MinCost if none of them can be parsed. Hashes are validated by
// validateUsers before the server starts, so an unparseable hash here means the
// configuration was changed to an invalid one after startup.
func maxBcryptCost(users map[string]config_util.Secret) int {
	cost := bcrypt.MinCost
	for _, hash := range users {
		c, err := bcrypt.Cost([]byte(hash))
		if err != nil {
			continue
		}
		if c > cost {
			cost = c
		}
	}
	return cost
}

// decoyHashes caches one bcrypt hash per cost, used for requests naming a user
// that is not configured.
//
// The cache is process-wide rather than per handler: the hashes are derived
// from a fixed password and hold no configuration, and generating one at a high
// cost is expensive enough to be worth doing only once.
type decoyHashes struct {
	mtx    sync.Mutex
	hashes map[int][]byte
}

var defaultDecoyHashes = newDecoyHashes()

func newDecoyHashes() *decoyHashes {
	return &decoyHashes{hashes: make(map[int][]byte)}
}

// forCost returns a hash with the given cost, generating it on first use. The
// generation happens at most once per cost for the lifetime of the process.
func (d *decoyHashes) forCost(cost int) ([]byte, error) {
	d.mtx.Lock()
	defer d.mtx.Unlock()

	if hash, ok := d.hashes[cost]; ok {
		return hash, nil
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(decoyPassword), cost)
	if err != nil {
		return nil, err
	}
	d.hashes[cost] = hash
	return hash, nil
}

type webHandler struct {
	tlsConfigPath string
	handler       http.Handler
	logger        *slog.Logger
	cache         *cache
	limiter       *rate.Limiter
	// decoys is nil in the default configuration and is then read from the
	// process-wide cache. Tests set it to isolate themselves from it.
	decoys *decoyHashes
	// bcryptMtx is there to ensure that bcrypt.CompareHashAndPassword is run
	// only once in parallel as this is CPU intensive.
	bcryptMtx sync.Mutex
}

// decoyHashes returns the cache this handler draws decoy hashes from.
func (u *webHandler) decoyHashes() *decoyHashes {
	if u.decoys != nil {
		return u.decoys
	}
	return defaultDecoyHashes
}

func (u *webHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	c, err := getConfig(u.tlsConfigPath)
	if err != nil {
		u.logger.Error("Unable to parse configuration", "err", err.Error())
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}

	if u.limiter != nil && !u.limiter.Allow() {
		http.Error(w, http.StatusText(http.StatusTooManyRequests), http.StatusTooManyRequests)
		return
	}

	// Configure http headers.
	for k, v := range c.HTTPConfig.Header {
		w.Header().Set(k, v)
	}

	if len(c.Users) == 0 {
		u.handler.ServeHTTP(w, r)
		return
	}

	user, pass, auth := r.BasicAuth()
	if auth {
		hashedPassword, validUser := c.Users[user]

		if !validUser {
			// The user is not found. Compare against a decoy hash so
			// that the request takes about as long as one naming a
			// configured user, which prevents user enumeration by
			// timing requests.
			//
			// The decoy is generated at the highest cost in use, so a
			// request for an unknown user is never answered faster
			// than one for a configured user. Where the configured
			// costs differ, the cheaper users are still answered
			// faster than the decoy; using a single cost for every
			// user avoids that.
			decoy, err := u.decoyHashes().forCost(maxBcryptCost(c.Users))
			if err != nil {
				u.logger.Error("Unable to generate decoy password hash", "err", err.Error())
				http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
				return
			}
			hashedPassword = config_util.Secret(decoy)
		}

		cacheKey := strings.Join(
			[]string{
				hex.EncodeToString([]byte(user)),
				hex.EncodeToString([]byte(hashedPassword)),
				hex.EncodeToString([]byte(pass)),
			}, ":")
		authOk, ok := u.cache.get(cacheKey)

		if !ok {
			// This user, hashedPassword, password is not cached.
			u.bcryptMtx.Lock()
			err := bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(pass))
			u.bcryptMtx.Unlock()

			authOk = validUser && err == nil
			u.cache.set(cacheKey, authOk)
		}

		if authOk && validUser {
			u.handler.ServeHTTP(w, r)
			return
		}
	}

	w.Header().Set("WWW-Authenticate", "Basic")
	http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
}
