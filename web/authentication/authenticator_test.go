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
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-kit/log"
)

func TestWithAuthentication(t *testing.T) {
	logger := &noOpLogger{}

	ts := []struct {
		Name               string
		Authenticator      Authenticator
		ExpectedStatusCode int
	}{
		{
			Name: "Accepting authenticator",
			Authenticator: AuthenticatorFunc(func(_ *http.Request) (bool, string, error) {
				return true, "", nil
			}),
			ExpectedStatusCode: http.StatusOK,
		},
		{
			Name: "Denying authenticator",
			Authenticator: AuthenticatorFunc(func(_ *http.Request) (bool, string, error) {
				return false, "", nil
			}),
			ExpectedStatusCode: http.StatusUnauthorized,
		},
		{
			Name: "Erroring authenticator",
			Authenticator: AuthenticatorFunc(func(_ *http.Request) (bool, string, error) {
				return false, "", errors.New("error authenticating")
			}),
			ExpectedStatusCode: http.StatusInternalServerError,
		},
	}

	for _, tt := range ts {
		t.Run(tt.Name, func(t *testing.T) {
			req := makeDefaultRequest(t)

			handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
			})

			rr := httptest.NewRecorder()
			authHandler := WithAuthentication(handler, tt.Authenticator, logger)
			authHandler.ServeHTTP(rr, req)
			got := rr.Result()

			if tt.ExpectedStatusCode != got.StatusCode {
				t.Errorf("Expected status code %q, got %q", tt.ExpectedStatusCode, got.Status)
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
