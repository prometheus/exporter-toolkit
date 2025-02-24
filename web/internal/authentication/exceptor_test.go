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
	"net/http/httptest"
	"testing"

	"github.com/prometheus/exporter-toolkit/web/internal/authentication/testhelpers"
)

func TestPathAuthenticationExceptor_IsExcepted(t *testing.T) {
	t.Parallel()

	tt := []struct {
		Name             string
		ExcludedPaths    []string
		URI              string
		ExpectedExcepted bool
	}{
		{
			Name:             "Path is not excepted when it doesn't match an excluded path",
			ExcludedPaths:    []string{"/somepath"},
			URI:              "/someotherpath",
			ExpectedExcepted: false,
		},
		{
			Name:             "Path is not excepted when its prefix matches an excluded path",
			ExcludedPaths:    []string{"/"},
			URI:              "/somepath",
			ExpectedExcepted: false,
		},
		{
			Name:             "Path is excepted when it exactly matches the only excluded path",
			ExcludedPaths:    []string{"/somepath"},
			URI:              "/somepath",
			ExpectedExcepted: true,
		},
		{
			Name:             "Path is excepted when it exactly matches one of the excluded paths",
			ExcludedPaths:    []string{"/somepath", "/someotherpath"},
			URI:              "/somepath",
			ExpectedExcepted: true,
		},
	}

	for _, tc := range tt {
		t.Run(tc.Name, func(t *testing.T) {
			t.Parallel()

			req, _ := http.NewRequest(http.MethodGet, tc.URI, nil)

			exceptor := NewPathExceptor(tc.ExcludedPaths)
			excepted := exceptor.IsExcepted(req)

			if tc.ExpectedExcepted && !excepted {
				t.Fatal("Expected path to be excepted, but it wasn't")
			}

			if !tc.ExpectedExcepted && excepted {
				t.Fatal("Expected path not to be excepted, but it was")
			}
		})
	}
}

func TestWithAuthenticationExceptor(t *testing.T) {
	t.Parallel()

	logger := testhelpers.NewNoOpLogger()

	tt := []struct {
		Name                        string
		Exceptor                    Exceptor
		ExpectedAuthenticatorCalled bool
	}{
		{
			Name: "Authenticator not called",
			Exceptor: ExceptorFunc(func(r *http.Request) bool {
				return true
			}),
			ExpectedAuthenticatorCalled: false,
		},
		{
			Name: "Authenticator called",
			Exceptor: ExceptorFunc(func(r *http.Request) bool {
				return false
			}),
			ExpectedAuthenticatorCalled: true,
		},
	}

	for _, tc := range tt {
		t.Run(tc.Name, func(t *testing.T) {
			t.Parallel()

			req := testhelpers.MakeDefaultRequest(t)

			handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
			})

			authenticatorCalled := false
			authenticator := AuthenticatorFunc(func(r *http.Request) (bool, string, *HTTPChallenge, error) {
				authenticatorCalled = true
				return false, "", nil, nil
			})

			rr := httptest.NewRecorder()
			exceptorHandler := WithExceptor(handler, authenticator, tc.Exceptor, logger)
			exceptorHandler.ServeHTTP(rr, req)

			if tc.ExpectedAuthenticatorCalled && !authenticatorCalled {
				t.Error("Expected authenticator to be called, but it wasn't")
			}

			if !tc.ExpectedAuthenticatorCalled && authenticatorCalled {
				t.Error("Expected authenticator not to be called, but it was")
			}
		})
	}
}
