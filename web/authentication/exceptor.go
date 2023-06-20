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
	"net/http"

	"github.com/go-kit/log"
	"github.com/go-kit/log/level"
)

type Exceptor interface {
	IsExcepted(r *http.Request) bool
}

type ExceptorFunc func(*http.Request) bool

func (f ExceptorFunc) IsExcepted(r *http.Request) bool {
	return f(r)
}

func WithExceptor(handler http.Handler, authenticator Authenticator, exceptor Exceptor, logger log.Logger) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if exceptor.IsExcepted(r) {
			level.Debug(logger).Log("msg", "Excepting request from authentication", "URI", r.RequestURI)
			handler.ServeHTTP(w, r)
			return
		}

		authHandler := WithAuthentication(handler, authenticator, logger)
		authHandler.ServeHTTP(w, r)
	})
}

type PathExceptor struct {
	excludedPaths map[string]bool
}

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
