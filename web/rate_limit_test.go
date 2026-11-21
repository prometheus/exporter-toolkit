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
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"
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

	addr := startTLSProtocolServer(t, server, configPath)

	requireStatus := func(what string, expected int) {
		t.Helper()
		r, err := http.Get("http://" + addr)
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

	// Putting it back applies it again. The burst spent before is still
	// spent, so a file that briefly lacks rate_limit, for example while it is
	// being rewritten, does not hand out a fresh burst.
	writeConfig(rateLimitedConfig)
	requireStatus("after restoring rate_limit", http.StatusTooManyRequests)
}

// TestRateLimiterKeepsItsBucket checks that a configuration change retunes the
// existing limiter instead of building a new one, which would hand out a fresh
// burst on every change and, with requests reading the file at different
// times, defeat the limit.
func TestRateLimiterKeepsItsBucket(t *testing.T) {
	h := &webHandler{logger: testlogger}
	c := RateLimiterConfig{Interval: time.Hour, Burst: 1}

	limiter := h.rateLimiter(c)
	if limiter == nil {
		t.Fatal("rateLimiter() = nil, expected a limiter")
	}
	if !limiter.Allow() {
		t.Fatal("first request refused")
	}

	if got := h.rateLimiter(c); got != limiter {
		t.Error("rateLimiter() built a new limiter for an unchanged configuration")
	}
	if got := h.rateLimiter(RateLimiterConfig{Burst: 5}); got != nil {
		t.Error("rateLimiter() = non-nil for a configuration without an interval")
	}
	if got := h.rateLimiter(RateLimiterConfig{Interval: time.Hour, Burst: 2}); got != limiter {
		t.Error("rateLimiter() built a new limiter for a changed configuration")
	}
	if got := limiter.Burst(); got != 2 {
		t.Errorf("burst = %d, expected 2", got)
	}
	// The token spent by the first request is still spent: raising the burst
	// does not refill the bucket.
	if limiter.Allow() {
		t.Error("changing the configuration refilled the token bucket")
	}
}
