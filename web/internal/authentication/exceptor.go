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

// Exceptor allows for selectively excluding HTTP requests from an operation.
type Exceptor interface {
	IsExcepted(r *http.Request) bool
}

type ExceptorFunc func(*http.Request) bool

func (f ExceptorFunc) IsExcepted(r *http.Request) bool {
	return f(r)
}

// WithExceptor implements an HTTP middleware which determines whether a request should bypass authentication based on the exclusion criteria defined by the exceptor.
func WithExceptor(handler http.Handler, authenticator Authenticator, exceptor Exceptor, logger *slog.Logger) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if exceptor.IsExcepted(r) {
			logger.Debug("Excepting request from authentication", "URI", r.RequestURI)
			handler.ServeHTTP(w, r)
			return
		}

		authHandler := WithAuthentication(handler, authenticator, logger)
		authHandler.ServeHTTP(w, r)
	})
}

// PathExceptor implements the exclusion logic based on a predetermined set of URL paths.
// A request is excepted when its URL path matches one of the excluded paths exactly.
type PathExceptor struct {
	excludedPaths map[string]bool
}

// IsExcepted determines that a request is excepted when its URL path matches one of the excluded paths exactly.
func (p PathExceptor) IsExcepted(r *http.Request) bool {
	return p.excludedPaths[r.URL.Path]
}

func NewPathExceptor(excludedPaths []string) Exceptor {
	excludedPathSet := make(map[string]bool, len(excludedPaths))
	for _, p := range excludedPaths {
		excludedPathSet[p] = true
	}

	return &PathExceptor{
		excludedPaths: excludedPathSet,
	}
}

var _ Exceptor = &PathExceptor{}
