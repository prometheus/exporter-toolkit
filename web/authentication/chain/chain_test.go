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

package chain

import (
	"errors"
	"net/http"
	"testing"

	"github.com/go-kit/log"
	"github.com/prometheus/exporter-toolkit/web/authentication"
)

func TestChainAuthenticator_Authenticate(t *testing.T) {
	firstAuthenticatorErr := errors.New("first authenticator error")
	secondAuthenticatorErr := errors.New("second authenticator error")

	ts := []struct {
		Name string

		AuthenticatorsFn func(t *testing.T) []authentication.Authenticator

		ExpectAuthenticated bool
		ExpectedResponse    string
		ExpectedError       error
	}{
		{
			Name: "First authenticator denies, the rest is not called, chain denies",
			AuthenticatorsFn: func(t *testing.T) []authentication.Authenticator {
				return []authentication.Authenticator{
					authentication.AuthenticatorFunc(func(r *http.Request) (bool, string, error) {
						return false, "First authenticator denied the request.", nil
					}),
					authentication.AuthenticatorFunc(func(r *http.Request) (bool, string, error) {
						t.Fatalf("Expected second authenticator not to be called, it was.")
						return true, "", nil
					}),
				}
			},
			ExpectAuthenticated: false,
			ExpectedResponse:    "First authenticator denied the request.",
			ExpectedError:       nil,
		},
		{
			Name: "First authenticator accepts, second is called and denies, chain denies",
			AuthenticatorsFn: func(t *testing.T) []authentication.Authenticator {
				return []authentication.Authenticator{
					authentication.AuthenticatorFunc(func(r *http.Request) (bool, string, error) {
						return true, "", nil
					}),
					authentication.AuthenticatorFunc(func(r *http.Request) (bool, string, error) {
						return false, "Second authenticator denied the request.", nil
					}),
				}
			},
			ExpectAuthenticated: false,
			ExpectedResponse:    "Second authenticator denied the request.",
			ExpectedError:       nil,
		},
		{
			Name: "All authenticators accept, chain accepts",
			AuthenticatorsFn: func(t *testing.T) []authentication.Authenticator {
				return []authentication.Authenticator{
					authentication.AuthenticatorFunc(func(r *http.Request) (bool, string, error) {
						return true, "", nil
					}),
					authentication.AuthenticatorFunc(func(r *http.Request) (bool, string, error) {
						return true, "", nil
					}),
				}
			},
			ExpectAuthenticated: true,
			ExpectedError:       nil,
		},
		{
			Name: "First authenticator returns an error, the rest is not called, chain returns an error",
			AuthenticatorsFn: func(t *testing.T) []authentication.Authenticator {
				return []authentication.Authenticator{
					authentication.AuthenticatorFunc(func(r *http.Request) (bool, string, error) {
						return false, "", firstAuthenticatorErr
					}),
					authentication.AuthenticatorFunc(func(r *http.Request) (bool, string, error) {
						t.Fatalf("Expected second authenticator not to be called, it was.")
						return true, "", nil
					}),
				}
			},
			ExpectAuthenticated: false,
			ExpectedError:       firstAuthenticatorErr,
		},
		{
			Name: "First authenticator accepts the request, second authenticator returns an error, chain returns an error",
			AuthenticatorsFn: func(t *testing.T) []authentication.Authenticator {
				return []authentication.Authenticator{
					authentication.AuthenticatorFunc(func(r *http.Request) (bool, string, error) {
						return true, "", nil
					}),
					authentication.AuthenticatorFunc(func(r *http.Request) (bool, string, error) {
						return false, "", secondAuthenticatorErr
					}),
				}
			},
			ExpectAuthenticated: false,
			ExpectedError:       secondAuthenticatorErr,
		},
	}

	for _, tt := range ts {
		t.Run(tt.Name, func(t *testing.T) {
			req := makeDefaultRequest(t)

			a := NewChainAuthenticator(tt.AuthenticatorsFn(t))
			authenticated, response, err := a.Authenticate(req)

			if err != nil && tt.ExpectedError == nil {
				t.Errorf("Got unexpected error: %v", err)
			}

			if err == nil && tt.ExpectedError != nil {
				t.Errorf("Expected error %v, got none", tt.ExpectedError)
			}

			if err != nil && tt.ExpectedError != nil && !errors.Is(err, tt.ExpectedError) {
				t.Errorf("Expected error %v, got %v", tt.ExpectedError, err)
			}

			if tt.ExpectedResponse != response {
				t.Errorf("Expected response %v, got %v", tt.ExpectedResponse, response)
			}

			if tt.ExpectAuthenticated != authenticated {
				t.Errorf("Expected authenticated %v, got %v", tt.ExpectAuthenticated, authenticated)
			}
		})
	}
}

type noOpLogger struct{}

func (noOpLogger) Log(...interface{}) error {
	return nil
}

var _ log.Logger = &noOpLogger{}

func makeDefaultRequest(t *testing.T) *http.Request {
	t.Helper()

	req, err := http.NewRequest(http.MethodGet, "/", nil)
	if err != nil {
		t.Fatalf("Error creating request: %v", err)
	}
	return req
}
