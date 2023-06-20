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
)

func TestPathAuthenticationExceptor_IsExcepted(t *testing.T) {
	ts := []struct {
		Name             string
		ExcludedPaths    []string
		URI              string
		ExpectedExcepted bool
	}{
		{
			Name:             "Path not excepted",
			ExcludedPaths:    []string{"/somepath"},
			URI:              "/someotherpath",
			ExpectedExcepted: false,
		},
		{
			Name:             "Exact path excepted (single)",
			ExcludedPaths:    []string{"/somepath"},
			URI:              "/somepath",
			ExpectedExcepted: true,
		},
		{
			Name:             "Exact path excepted (multiple)",
			ExcludedPaths:    []string{"/somepath", "/someotherpath"},
			URI:              "/somepath",
			ExpectedExcepted: true,
		},
	}

	for _, tt := range ts {
		t.Run(tt.Name, func(t *testing.T) {
			tt := tt
			req, _ := http.NewRequest(http.MethodGet, tt.URI, nil)

			exceptor := NewPathExceptor(tt.ExcludedPaths)
			excepted := exceptor.IsExcepted(req)

			if tt.ExpectedExcepted && !excepted {
				t.Fatal("Expected path to be excepted, it wasn't")
			}

			if !tt.ExpectedExcepted && excepted {
				t.Fatalf("Expected path to not be excepted, it was")
			}
		})
	}
}

func TestWithAuthenticationExceptor(t *testing.T) {
	logger := &noOpLogger{}

	ts := []struct {
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

	for _, tt := range ts {
		t.Run(tt.Name, func(t *testing.T) {
			req := makeDefaultRequest(t)

			handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
			})

			authenticatorCalled := false
			authenticator := AuthenticatorFunc(func(r *http.Request) (bool, string, error) {
				authenticatorCalled = true
				return false, "", nil
			})

			rr := httptest.NewRecorder()
			exceptorHandler := WithExceptor(handler, authenticator, tt.Exceptor, logger)
			exceptorHandler.ServeHTTP(rr, req)

			if tt.ExpectedAuthenticatorCalled && !authenticatorCalled {
				t.Error("Expected authenticator to be called, it wasn't")
			}

			if !tt.ExpectedAuthenticatorCalled && authenticatorCalled {
				t.Error("Expected authenticator to not be called, it was")
			}
		})
	}
}
