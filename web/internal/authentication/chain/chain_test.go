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
	"reflect"
	"testing"

	"github.com/prometheus/exporter-toolkit/web/internal/authentication"
	"github.com/prometheus/exporter-toolkit/web/internal/authentication/testhelpers"
)

func TestChainAuthenticator_Authenticate(t *testing.T) {
	t.Parallel()

	firstAuthenticatorErr := errors.New("first authenticator error")
	firstAuthenticatorHTTPChallenge := &authentication.HTTPChallenge{
		Scheme: "FirstAuthenticator",
	}

	secondAuthenticatorErr := errors.New("second authenticator error")
	secondAuthenticatorHTTPChallenge := &authentication.HTTPChallenge{
		Scheme: "SecondAuthenticator",
	}

	tt := []struct {
		Name string

		AuthenticatorsFn func(t *testing.T) []authentication.Authenticator

		ExpectAuthenticated   bool
		ExpectedDenyReason    string
		ExpectedHTTPChallenge *authentication.HTTPChallenge
		ExpectedError         error
	}{
		{
			Name: "First authenticator denies, second accepts, only first authenticator is called, chain denies",
			AuthenticatorsFn: func(t *testing.T) []authentication.Authenticator {
				return []authentication.Authenticator{
					authentication.AuthenticatorFunc(func(r *http.Request) (bool, string, *authentication.HTTPChallenge, error) {
						return false, "First authenticator denied the request.", nil, nil
					}),
					authentication.AuthenticatorFunc(func(r *http.Request) (bool, string, *authentication.HTTPChallenge, error) {
						t.Fatalf("Expected second authenticator not to be called, but it was.")
						return true, "", nil, nil
					}),
				}
			},
			ExpectAuthenticated:   false,
			ExpectedDenyReason:    "First authenticator denied the request.",
			ExpectedHTTPChallenge: nil,
			ExpectedError:         nil,
		},
		{
			Name: "First authenticator denies and returns http challenge, second accepts, only first authenticator is called, chain denies and propagates http challenge",
			AuthenticatorsFn: func(t *testing.T) []authentication.Authenticator {
				return []authentication.Authenticator{
					authentication.AuthenticatorFunc(func(r *http.Request) (bool, string, *authentication.HTTPChallenge, error) {
						return false, "First authenticator denied the request.", firstAuthenticatorHTTPChallenge, nil
					}),
					authentication.AuthenticatorFunc(func(r *http.Request) (bool, string, *authentication.HTTPChallenge, error) {
						t.Fatalf("Expected second authenticator not to be called, but it was.")
						return true, "", nil, nil
					}),
				}
			},
			ExpectAuthenticated:   false,
			ExpectedDenyReason:    "First authenticator denied the request.",
			ExpectedHTTPChallenge: firstAuthenticatorHTTPChallenge,
			ExpectedError:         nil,
		},
		{
			Name: "First authenticator denies, second denies, only first authenticator is called, chain denies",
			AuthenticatorsFn: func(t *testing.T) []authentication.Authenticator {
				return []authentication.Authenticator{
					authentication.AuthenticatorFunc(func(r *http.Request) (bool, string, *authentication.HTTPChallenge, error) {
						return false, "First authenticator denied the request.", nil, nil
					}),
					authentication.AuthenticatorFunc(func(r *http.Request) (bool, string, *authentication.HTTPChallenge, error) {
						t.Fatalf("Expected second authenticator not to be called, but it was.")
						return true, "Second authenticator denied the request.", nil, nil
					}),
				}
			},
			ExpectAuthenticated:   false,
			ExpectedDenyReason:    "First authenticator denied the request.",
			ExpectedHTTPChallenge: nil,
			ExpectedError:         nil,
		},
		{
			Name: "First authenticator denies, second denies, both return http challenges, only first authenticator is called, chain denies and only propagates first http challenge",
			AuthenticatorsFn: func(t *testing.T) []authentication.Authenticator {
				return []authentication.Authenticator{
					authentication.AuthenticatorFunc(func(r *http.Request) (bool, string, *authentication.HTTPChallenge, error) {
						return false, "First authenticator denied the request.", firstAuthenticatorHTTPChallenge, nil
					}),
					authentication.AuthenticatorFunc(func(r *http.Request) (bool, string, *authentication.HTTPChallenge, error) {
						t.Fatalf("Expected second authenticator not to be called, but it was.")
						return true, "Second authenticator denied the request.", secondAuthenticatorHTTPChallenge, nil
					}),
				}
			},
			ExpectAuthenticated:   false,
			ExpectedDenyReason:    "First authenticator denied the request.",
			ExpectedHTTPChallenge: firstAuthenticatorHTTPChallenge,
			ExpectedError:         nil,
		},
		{
			Name: "First authenticator accepts, second is called and denies, chain denies",
			AuthenticatorsFn: func(t *testing.T) []authentication.Authenticator {
				return []authentication.Authenticator{
					authentication.AuthenticatorFunc(func(r *http.Request) (bool, string, *authentication.HTTPChallenge, error) {
						return true, "", nil, nil
					}),
					authentication.AuthenticatorFunc(func(r *http.Request) (bool, string, *authentication.HTTPChallenge, error) {
						return false, "Second authenticator denied the request.", nil, nil
					}),
				}
			},
			ExpectAuthenticated:   false,
			ExpectedDenyReason:    "Second authenticator denied the request.",
			ExpectedHTTPChallenge: nil,
			ExpectedError:         nil,
		},
		{
			Name: "First authenticator accepts, second is called, denies and returns http challenge, chain denies and propagates http challenge",
			AuthenticatorsFn: func(t *testing.T) []authentication.Authenticator {
				return []authentication.Authenticator{
					authentication.AuthenticatorFunc(func(r *http.Request) (bool, string, *authentication.HTTPChallenge, error) {
						return true, "", nil, nil
					}),
					authentication.AuthenticatorFunc(func(r *http.Request) (bool, string, *authentication.HTTPChallenge, error) {
						return false, "Second authenticator denied the request.", secondAuthenticatorHTTPChallenge, nil
					}),
				}
			},
			ExpectAuthenticated:   false,
			ExpectedDenyReason:    "Second authenticator denied the request.",
			ExpectedHTTPChallenge: secondAuthenticatorHTTPChallenge,
			ExpectedError:         nil,
		},
		{
			Name: "All authenticators accept, chain accepts",
			AuthenticatorsFn: func(t *testing.T) []authentication.Authenticator {
				return []authentication.Authenticator{
					authentication.AuthenticatorFunc(func(r *http.Request) (bool, string, *authentication.HTTPChallenge, error) {
						return true, "", nil, nil
					}),
					authentication.AuthenticatorFunc(func(r *http.Request) (bool, string, *authentication.HTTPChallenge, error) {
						return true, "", nil, nil
					}),
				}
			},
			ExpectAuthenticated:   true,
			ExpectedDenyReason:    "",
			ExpectedHTTPChallenge: nil,
			ExpectedError:         nil,
		},
		{
			Name: "First authenticator returns an error, the rest is not called, chain returns an error",
			AuthenticatorsFn: func(t *testing.T) []authentication.Authenticator {
				return []authentication.Authenticator{
					authentication.AuthenticatorFunc(func(r *http.Request) (bool, string, *authentication.HTTPChallenge, error) {
						return false, "", nil, firstAuthenticatorErr
					}),
					authentication.AuthenticatorFunc(func(r *http.Request) (bool, string, *authentication.HTTPChallenge, error) {
						t.Fatalf("Expected second authenticator not to be called, but it was.")
						return true, "", nil, nil
					}),
				}
			},
			ExpectAuthenticated:   false,
			ExpectedDenyReason:    "",
			ExpectedHTTPChallenge: nil,
			ExpectedError:         firstAuthenticatorErr,
		},
		{
			Name: "First authenticator accepts the request, second authenticator returns an error, chain returns an error",
			AuthenticatorsFn: func(t *testing.T) []authentication.Authenticator {
				return []authentication.Authenticator{
					authentication.AuthenticatorFunc(func(r *http.Request) (bool, string, *authentication.HTTPChallenge, error) {
						return true, "", nil, nil
					}),
					authentication.AuthenticatorFunc(func(r *http.Request) (bool, string, *authentication.HTTPChallenge, error) {
						return false, "", nil, secondAuthenticatorErr
					}),
				}
			},
			ExpectAuthenticated:   false,
			ExpectedDenyReason:    "",
			ExpectedHTTPChallenge: nil,
			ExpectedError:         secondAuthenticatorErr,
		},
	}

	for _, tc := range tt {
		t.Run(tc.Name, func(t *testing.T) {
			t.Parallel()

			req := testhelpers.MakeDefaultRequest(t)

			a := NewChainAuthenticator(tc.AuthenticatorsFn(t))
			authenticated, denyReason, httpChallenge, err := a.Authenticate(req)

			if !reflect.DeepEqual(err, tc.ExpectedError) {
				t.Errorf("Expected error %v, got %v", tc.ExpectedError, err)
			}

			if tc.ExpectAuthenticated != authenticated {
				t.Errorf("Expected authenticated %t, got %t", tc.ExpectAuthenticated, authenticated)
			}

			if tc.ExpectedDenyReason != denyReason {
				t.Errorf("Expected deny reason %q, got %q", tc.ExpectedDenyReason, denyReason)
			}

			if !reflect.DeepEqual(httpChallenge, tc.ExpectedHTTPChallenge) {
				t.Errorf("Expected http challenge %v, got %v", tc.ExpectedHTTPChallenge, httpChallenge)
			}
		})
	}
}
