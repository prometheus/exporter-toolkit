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
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"

	"github.com/prometheus/exporter-toolkit/web/internal/authentication/testhelpers"
)

func TestWithAuthentication(t *testing.T) {
	t.Parallel()

	logger := testhelpers.NewNoOpLogger()

	tt := []struct {
		Name                          string
		Authenticator                 Authenticator
		ExpectedStatusCode            int
		ExpectedBody                  string
		ExpectedWWWAuthenticateHeader string
	}{
		{
			Name: "Accepting authenticator",
			Authenticator: AuthenticatorFunc(func(_ *http.Request) (bool, string, *HTTPChallenge, error) {
				return true, "", nil, nil
			}),
			ExpectedStatusCode:            http.StatusOK,
			ExpectedBody:                  "",
			ExpectedWWWAuthenticateHeader: "",
		},
		{
			Name: "Denying authenticator without http challenge",
			Authenticator: AuthenticatorFunc(func(_ *http.Request) (bool, string, *HTTPChallenge, error) {
				return false, "deny reason", nil, nil
			}),
			ExpectedStatusCode:            http.StatusUnauthorized,
			ExpectedBody:                  "deny reason\n",
			ExpectedWWWAuthenticateHeader: "",
		},
		{
			Name: "Denying authenticator with http challenge",
			Authenticator: AuthenticatorFunc(func(_ *http.Request) (bool, string, *HTTPChallenge, error) {
				httpChallenge := &HTTPChallenge{
					Scheme: "test",
				}
				return false, "deny reason", httpChallenge, nil
			}),
			ExpectedStatusCode:            http.StatusUnauthorized,
			ExpectedBody:                  "deny reason\n",
			ExpectedWWWAuthenticateHeader: "test",
		},
		{
			Name: "Erroring authenticator",
			Authenticator: AuthenticatorFunc(func(_ *http.Request) (bool, string, *HTTPChallenge, error) {
				return false, "", nil, errors.New("error authenticating")
			}),
			ExpectedStatusCode:            http.StatusInternalServerError,
			ExpectedBody:                  "Internal Server Error\n",
			ExpectedWWWAuthenticateHeader: "",
		},
	}

	for _, tc := range tt {
		t.Run(tc.Name, func(t *testing.T) {
			t.Parallel()

			req := testhelpers.MakeDefaultRequest(t)

			handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
			})

			rr := httptest.NewRecorder()
			authHandler := WithAuthentication(handler, tc.Authenticator, logger)
			authHandler.ServeHTTP(rr, req)
			gotResult := rr.Result()

			gotBodyBytes, err := io.ReadAll(gotResult.Body)
			if err != nil {
				t.Fatalf("unexpected error reading response body: %v", err)
			}
			gotBody := string(gotBodyBytes)

			gotWWWAuthenticateHeader := gotResult.Header.Get("WWW-Authenticate")

			if tc.ExpectedStatusCode != gotResult.StatusCode {
				t.Errorf("Expected status code %q, got %q", tc.ExpectedStatusCode, gotResult.StatusCode)
			}

			if tc.ExpectedBody != gotBody {
				t.Errorf("Expected body %q, got %q", tc.ExpectedBody, gotBody)
			}

			if !reflect.DeepEqual(tc.ExpectedWWWAuthenticateHeader, gotWWWAuthenticateHeader) {
				t.Errorf("Expected 'WWW-Authenticate' header %v, got %v", tc.ExpectedWWWAuthenticateHeader, gotWWWAuthenticateHeader)
			}
		})
	}
}
