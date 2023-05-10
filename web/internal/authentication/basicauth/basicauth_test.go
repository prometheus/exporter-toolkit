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
	"net/http"
	"net/http/httptest"
	"reflect"
	"sync"
	"testing"

	config_util "github.com/prometheus/common/config"
	"github.com/prometheus/exporter-toolkit/web/internal/authentication"
	"github.com/prometheus/exporter-toolkit/web/internal/authentication/testhelpers"
)

func TestBasicAuthAuthenticator_Authenticate(t *testing.T) {
	t.Parallel()

	tt := []struct {
		Name string

		Users map[string]config_util.Secret

		RequestFn func(*testing.T) *http.Request

		ExpectAuthenticated   bool
		ExpectedDenyReason    string
		ExpectedHTTPChallenge *authentication.HTTPChallenge
		ExpectedError         error
	}{
		{
			Name: "No basic auth",
			Users: map[string]config_util.Secret{
				"alice": "$2y$12$1DpfPeqF9HzHJt.EWswy1exHluGfbhnn3yXhR7Xes6m3WJqFg0Wby",
				"bob":   "$2y$18$4VeFDzXIoPHKnKTU3O3GH.N.vZu06CVqczYZ8WvfzrddFU6tGqjR.",
			},
			RequestFn:           testhelpers.MakeDefaultRequest,
			ExpectAuthenticated: false,
			ExpectedDenyReason:  "Unauthorized",
			ExpectedHTTPChallenge: &authentication.HTTPChallenge{
				Scheme: "Basic",
			},
			ExpectedError: nil,
		},
		{
			Name: "Existing user, correct password",
			Users: map[string]config_util.Secret{
				"alice": "$2y$12$1DpfPeqF9HzHJt.EWswy1exHluGfbhnn3yXhR7Xes6m3WJqFg0Wby",
				"bob":   "$2y$18$4VeFDzXIoPHKnKTU3O3GH.N.vZu06CVqczYZ8WvfzrddFU6tGqjR.",
			},
			RequestFn: func(t *testing.T) *http.Request {
				t.Helper()

				req := testhelpers.MakeDefaultRequest(t)
				req.SetBasicAuth("alice", "alice123")

				return req
			},
			ExpectAuthenticated:   true,
			ExpectedDenyReason:    "",
			ExpectedHTTPChallenge: nil,
			ExpectedError:         nil,
		},
		{
			Name: "Existing user, incorrect password",
			Users: map[string]config_util.Secret{
				"alice": "$2y$12$1DpfPeqF9HzHJt.EWswy1exHluGfbhnn3yXhR7Xes6m3WJqFg0Wby",
				"bob":   "$2y$18$4VeFDzXIoPHKnKTU3O3GH.N.vZu06CVqczYZ8WvfzrddFU6tGqjR.",
			},
			RequestFn: func(t *testing.T) *http.Request {
				t.Helper()

				req := testhelpers.MakeDefaultRequest(t)
				req.SetBasicAuth("alice", "alice1234")

				return req
			},
			ExpectAuthenticated: false,
			ExpectedDenyReason:  "Unauthorized",
			ExpectedHTTPChallenge: &authentication.HTTPChallenge{
				Scheme: "Basic",
			},
			ExpectedError: nil,
		},
		{
			Name: "Nonexisting user",
			Users: map[string]config_util.Secret{
				"bob":   "$2y$18$4VeFDzXIoPHKnKTU3O3GH.N.vZu06CVqczYZ8WvfzrddFU6tGqjR.",
				"carol": "$2y$10$qRTBuFoULoYNA7AQ/F3ck.trZBPyjV64.oA4ZsSBCIWvXuvQlQTuu",
			},
			RequestFn: func(t *testing.T) *http.Request {
				t.Helper()

				req := testhelpers.MakeDefaultRequest(t)
				req.SetBasicAuth("alice", "alice123")

				return req
			},
			ExpectAuthenticated: false,
			ExpectedDenyReason:  "Unauthorized",
			ExpectedHTTPChallenge: &authentication.HTTPChallenge{
				Scheme: "Basic",
			},
			ExpectedError: nil,
		},
	}

	for _, tc := range tt {
		t.Run(tc.Name, func(t *testing.T) {
			t.Parallel()

			req := tc.RequestFn(t)

			a := NewBasicAuthAuthenticator(tc.Users)
			authenticated, denyReason, httpChallenge, err := a.Authenticate(req)

			if !reflect.DeepEqual(err, tc.ExpectedError) {
				t.Fatalf("Expected error %v, got %v", tc.ExpectedError, err)
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

// TestWithAuthentication_BasicAuthAuthenticator_Cache validates that the cache is working by calling a password
// protected endpoint multiple times.
func TestWithAuthentication_BasicAuthAuthenticator_Cache(t *testing.T) {
	t.Parallel()

	logger := testhelpers.NewNoOpLogger()

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	users := map[string]config_util.Secret{
		"alice": "$2y$12$1DpfPeqF9HzHJt.EWswy1exHluGfbhnn3yXhR7Xes6m3WJqFg0Wby",
		"bob":   "$2y$18$4VeFDzXIoPHKnKTU3O3GH.N.vZu06CVqczYZ8WvfzrddFU6tGqjR.",
		"carol": "$2y$10$qRTBuFoULoYNA7AQ/F3ck.trZBPyjV64.oA4ZsSBCIWvXuvQlQTuu",
		"dave":  "$2y$10$2UXri9cIDdgeKjBo4Rlpx.U3ZLDV8X1IxKmsfOvhcM5oXQt/mLmXq",
	}

	authenticator := NewBasicAuthAuthenticator(users)
	authHandler := authentication.WithAuthentication(handler, authenticator, logger)

	login := func(username, password string, expectedStatusCode int) {
		req := testhelpers.MakeDefaultRequest(t)
		req.SetBasicAuth(username, password)

		rr := httptest.NewRecorder()
		authHandler.ServeHTTP(rr, req)

		res := rr.Result()
		if expectedStatusCode != res.StatusCode {
			t.Fatalf("Expected status code %d, got %d", expectedStatusCode, res.StatusCode)
		}
	}

	// Initial logins, checking that it just works.
	login("alice", "alice123", 200)
	login("alice", "alice1234", 401)

	var (
		start = make(chan struct{})
		wg    sync.WaitGroup
	)
	wg.Add(300)
	for i := 0; i < 150; i++ {
		go func() {
			<-start
			login("alice", "alice123", 200)
			wg.Done()
		}()
		go func() {
			<-start
			login("alice", "alice1234", 401)
			wg.Done()
		}()
	}
	close(start)
	wg.Wait()
}

// TestWithAuthentication_BasicAuthAuthenticator_WithFakepassword validates that we can't login the "fakepassword" used
// to prevent user enumeration.
func TestWithAuthentication_BasicAuthAuthenticator_WithFakepassword(t *testing.T) {
	t.Parallel()

	logger := testhelpers.NewNoOpLogger()

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	users := map[string]config_util.Secret{
		"alice": "$2y$12$1DpfPeqF9HzHJt.EWswy1exHluGfbhnn3yXhR7Xes6m3WJqFg0Wby",
		"bob":   "$2y$18$4VeFDzXIoPHKnKTU3O3GH.N.vZu06CVqczYZ8WvfzrddFU6tGqjR.",
		"carol": "$2y$10$qRTBuFoULoYNA7AQ/F3ck.trZBPyjV64.oA4ZsSBCIWvXuvQlQTuu",
		"dave":  "$2y$10$2UXri9cIDdgeKjBo4Rlpx.U3ZLDV8X1IxKmsfOvhcM5oXQt/mLmXq",
	}

	authenticator := NewBasicAuthAuthenticator(users)
	authHandler := authentication.WithAuthentication(handler, authenticator, logger)

	expectedStatusCode := http.StatusUnauthorized
	login := func() {
		req := testhelpers.MakeDefaultRequest(t)
		req.SetBasicAuth("fakeuser", "fakepassword")

		rr := httptest.NewRecorder()
		authHandler.ServeHTTP(rr, req)

		res := rr.Result()
		if expectedStatusCode != res.StatusCode {
			t.Fatalf("Expected status code %d, got %d", expectedStatusCode, res.StatusCode)
		}
	}

	// Login with a cold cache.
	login()
	// Login with the response cached.
	login()
}

// TestWithAuthentication_BasicAuthAuthenticator_BypassBasicAuthVuln tests for CVE-2022-46146.
func TestWithAuthentication_BasicAuthAuthenticator_BypassBasicAuthVuln(t *testing.T) {
	t.Parallel()

	logger := testhelpers.NewNoOpLogger()

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	users := map[string]config_util.Secret{
		"alice": "$2y$12$1DpfPeqF9HzHJt.EWswy1exHluGfbhnn3yXhR7Xes6m3WJqFg0Wby",
		"bob":   "$2y$18$4VeFDzXIoPHKnKTU3O3GH.N.vZu06CVqczYZ8WvfzrddFU6tGqjR.",
		"carol": "$2y$10$qRTBuFoULoYNA7AQ/F3ck.trZBPyjV64.oA4ZsSBCIWvXuvQlQTuu",
		"dave":  "$2y$10$2UXri9cIDdgeKjBo4Rlpx.U3ZLDV8X1IxKmsfOvhcM5oXQt/mLmXq",
	}

	authenticator := NewBasicAuthAuthenticator(users)
	authHandler := authentication.WithAuthentication(handler, authenticator, logger)

	expectedStatusCode := http.StatusUnauthorized
	login := func(username, password string) {
		req := testhelpers.MakeDefaultRequest(t)
		req.SetBasicAuth(username, password)

		rr := httptest.NewRecorder()
		authHandler.ServeHTTP(rr, req)

		res := rr.Result()
		if expectedStatusCode != res.StatusCode {
			t.Fatalf("Expected status code %d, got %d", expectedStatusCode, res.StatusCode)
		}
	}

	// Poison the cache.
	login("alice$2y$12$1DpfPeqF9HzHJt.EWswy1exHluGfbhnn3yXhR7Xes6m3WJqFg0Wby", "fakepassword")
	// Login with a wrong password.
	login("alice", "$2y$10$QOauhQNbBCuQDKes6eFzPeMqBSjb7Mr5DUmpZ/VcEd00UAV/LDeSifakepassword")
}
