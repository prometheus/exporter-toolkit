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

package authentication

import (
	"log/slog"
	"net/http"
)

// HTTPChallenge contains information which can used by an HTTP server to challenge a client request using a challenge-response authentication framework.
// https://datatracker.ietf.org/doc/html/rfc7235#section-2.1
type HTTPChallenge struct {
	Scheme string
}

type Authenticator interface {
	Authenticate(*http.Request) (bool, string, *HTTPChallenge, error)
}

type AuthenticatorFunc func(r *http.Request) (bool, string, *HTTPChallenge, error)

func (f AuthenticatorFunc) Authenticate(r *http.Request) (bool, string, *HTTPChallenge, error) {
	return f(r)
}

func WithAuthentication(handler http.Handler, authenticator Authenticator, logger *slog.Logger) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ok, denyReason, httpChallenge, err := authenticator.Authenticate(r)
		if err != nil {
			logger.Error("Unable to authenticate", "URI", r.RequestURI, "err", err.Error())
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}

		if ok {
			handler.ServeHTTP(w, r)
			return
		}

		if httpChallenge != nil {
			w.Header().Set("WWW-Authenticate", httpChallenge.Scheme)
		}

		logger.Warn("Unauthenticated request", "URI", r.RequestURI, "denyReason", denyReason)
		http.Error(w, denyReason, http.StatusUnauthorized)
	})
}
