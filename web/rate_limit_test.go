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
	"os"
	"path/filepath"
	"testing"
)

const (
	// rateLimitedConfig allows a single request and then refuses everything
	// for an hour, which makes the limiter's state easy to observe.
	rateLimitedConfig = "rate_limit:\n  interval: 1h\n  burst: 1\n"
	unlimitedConfig   = "http_server_config:\n  http2: true\n"
)

// TestRateLimitIsReloaded checks that a change to rate_limit takes effect
// without a restart. The configuration file is documented as being read on
// every request, and every other key behaves that way.
func TestRateLimitIsReloaded(t *testing.T) {
	configPath := filepath.Join(t.TempDir(), "web-config.yml")
	writeConfig := func(content string) {
		t.Helper()
		if err := os.WriteFile(configPath, []byte(content), 0o600); err != nil {
			t.Fatalf("Unable to write config: %v", err)
		}
	}
	writeConfig(rateLimitedConfig)

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
			WebConfigFile:      &configPath,
		}
		ListenAndServe(server, &flags, testlogger)
		close(done)
	}()

	waitForPort(t, port)

	requireStatus := func(what string, expected int) {
		t.Helper()
		r, err := http.Get("http://localhost" + port)
		if err != nil {
			t.Fatal(err)
		}
		r.Body.Close()
		if r.StatusCode != expected {
			t.Fatalf("%s: got status %d, expected %d", what, r.StatusCode, expected)
		}
	}

	// The burst is spent by the first request.
	requireStatus("first request", http.StatusOK)
	requireStatus("second request", http.StatusTooManyRequests)

	// Removing rate_limit lifts the limit.
	writeConfig(unlimitedConfig)
	requireStatus("after removing rate_limit", http.StatusOK)
	requireStatus("after removing rate_limit, again", http.StatusOK)

	// Putting it back applies it again, with a fresh burst.
	writeConfig(rateLimitedConfig)
	requireStatus("after restoring rate_limit", http.StatusOK)
	requireStatus("after restoring rate_limit, again", http.StatusTooManyRequests)
}

// TestRateLimiterUnchangedConfigKeepsItsBucket checks that an unchanged
// configuration does not rebuild the limiter, which would hand out a fresh
// burst on every request and defeat the limit.
func TestRateLimiterUnchangedConfigKeepsItsBucket(t *testing.T) {
	h := &webHandler{logger: testlogger}
	c := RateLimiterConfig{Interval: 1, Burst: 1}

	first := h.rateLimiter(c)
	if first == nil {
		t.Fatal("rateLimiter() = nil, expected a limiter")
	}
	if second := h.rateLimiter(c); second != first {
		t.Error("rateLimiter() built a new limiter for an unchanged configuration")
	}
	if disabled := h.rateLimiter(RateLimiterConfig{}); disabled != nil {
		t.Error("rateLimiter() = non-nil for a configuration without an interval")
	}
}
