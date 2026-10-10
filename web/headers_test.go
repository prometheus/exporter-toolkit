// Copyright The Prometheus Authors
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

package web

import (
	"context"
	"net/http"
	"testing"
)

// TestHeadersOnRateLimitedResponse checks that the configured headers are set
// on a response that the rate limiter turns away. A header policy such as
// Strict-Transport-Security is meant to hold for every response from the
// endpoint, not only for the ones that are served.
func TestHeadersOnRateLimitedResponse(t *testing.T) {
	server := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Write([]byte("Hello World!"))
		}),
	}

	done := make(chan struct{})
	t.Cleanup(func() {
		if err := server.Shutdown(context.Background()); err != nil {
			t.Fatal(err)
		}
		<-done
	})

	go func() {
		flags := FlagConfig{
			WebListenAddresses: &([]string{port}),
			WebSystemdSocket:   OfBool(false),
			WebConfigFile:      OfString("testdata/web_config_rate_limiter_headers.yaml"),
		}
		ListenAndServe(server, &flags, testlogger)
		close(done)
	}()

	waitForPort(t, port)

	// The burst is 1 over an interval of an hour, so the first request is
	// served and every one after it is rate limited.
	get := func() *http.Response {
		t.Helper()
		r, err := http.Get("http://localhost" + port)
		if err != nil {
			t.Fatal(err)
		}
		r.Body.Close()
		return r
	}

	served := get()
	if served.StatusCode != http.StatusOK {
		t.Fatalf("first request: got status %d, expected %d", served.StatusCode, http.StatusOK)
	}

	limited := get()
	if limited.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("second request: got status %d, expected %d", limited.StatusCode, http.StatusTooManyRequests)
	}

	for _, header := range []string{"X-Frame-Options", "Strict-Transport-Security"} {
		want := served.Header.Get(header)
		if want == "" {
			t.Fatalf("%s was not set on the served response", header)
		}
		if got := limited.Header.Get(header); got != want {
			t.Errorf("%s on the rate limited response = %q, expected %q", header, got, want)
		}
	}
}
