// Copyright 2023 The Prometheus Authors
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

package basicauth

import (
	"encoding/hex"
	"net/http"
	"strings"
	"sync"

	"github.com/prometheus/common/config"
	"github.com/prometheus/exporter-toolkit/web/authentication"
	"golang.org/x/crypto/bcrypt"
)

type BasicAuthAuthenticator struct {
	users map[string]config.Secret

	cache *cache
	// bcryptMtx is there to ensure that bcrypt.CompareHashAndPassword is run
	// only once in parallel as this is CPU intensive.
	bcryptMtx sync.Mutex
}

func (b *BasicAuthAuthenticator) Authenticate(r *http.Request) (bool, string, error) {
	user, pass, auth := r.BasicAuth()

	if !auth {
		return false, "No credentials in request", nil
	}

	hashedPassword, validUser := b.users[user]

	if !validUser {
		// The user is not found. Use a fixed password hash to
		// prevent user enumeration by timing requests.
		// This is a bcrypt-hashed version of "fakepassword".
		hashedPassword = "$2y$10$QOauhQNbBCuQDKes6eFzPeMqBSjb7Mr5DUmpZ/VcEd00UAV/LDeSi"
	}

	cacheKey := strings.Join(
		[]string{
			hex.EncodeToString([]byte(user)),
			hex.EncodeToString([]byte(hashedPassword)),
			hex.EncodeToString([]byte(pass)),
		}, ":")
	authOk, ok := b.cache.get(cacheKey)

	if !ok {
		// This user, hashedPassword, password is not cached.
		b.bcryptMtx.Lock()
		err := bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(pass))
		b.bcryptMtx.Unlock()

		authOk = validUser && err == nil
		b.cache.set(cacheKey, authOk)
	}

	if authOk && validUser {
		return true, "", nil
	}

	return false, "Invalid credentials", nil
}

func NewBasicAuthAuthenticator(users map[string]config.Secret) authentication.Authenticator {
	return &BasicAuthAuthenticator{
		cache: newCache(),
		users: users,
	}
}

var _ authentication.Authenticator = &BasicAuthAuthenticator{}
