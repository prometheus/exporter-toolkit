// Copyright 2020 The Prometheus Authors
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

package https

import (
	"net/http"

	"github.com/go-kit/kit/log"
	"github.com/prometheus/client_golang/prometheus"
	"golang.org/x/crypto/bcrypt"
)

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

type userAuthRoundtrip struct {
	tlsConfigPath   string
	handler         http.Handler
	logger          log.Logger
	failuresCounter prometheus.Counter
}

func (u *userAuthRoundtrip) instrument(r prometheus.Registerer) {
	u.failuresCounter = prometheus.NewCounter(
		prometheus.CounterOpts{
			Namespace: "prometheus_toolkit",
			Subsystem: "https",
			Name:      "request_basic_authentication_failures_total",
			Help:      "Total number of requests rejected by basic authentication because of wrong username, password, or configuration.",
		},
	)
	if r != nil {
		r.MustRegister(u.failuresCounter)
	}
}

func (u *userAuthRoundtrip) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	c, err := getConfig(u.tlsConfigPath)
	if err != nil {
		u.failuresCounter.Inc()
		u.logger.Log("msg", "Unable to parse configuration", "err", err)
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}

	if len(c.Users) == 0 {
		u.handler.ServeHTTP(w, r)
		return
	}

	user, pass, auth := r.BasicAuth()
	if auth {
		if hashedPassword, ok := c.Users[user]; ok {
			if err := bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(pass)); err == nil {
				u.handler.ServeHTTP(w, r)
				return
			}
		}
	}

	u.failuresCounter.Inc()
	w.Header().Set("WWW-Authenticate", "Basic")
	http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
}
