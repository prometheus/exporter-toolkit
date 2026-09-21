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

package bootstrap

import (
	"bytes"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/alecthomas/kingpin/v2"
)

// waitTimeout bounds how long a test waits for a request to reach the handler,
// so that a regression in the limiter fails the test instead of hanging until
// the package timeout.
const waitTimeout = 10 * time.Second

// blockingHandler serves requests that block until release is closed, so that a
// test can hold a known number of them in flight at once.
type blockingHandler struct {
	entered chan struct{}
	release chan struct{}
}

func newBlockingHandler(capacity int) *blockingHandler {
	return &blockingHandler{
		entered: make(chan struct{}, capacity),
		release: make(chan struct{}),
	}
}

func (h *blockingHandler) ServeHTTP(w http.ResponseWriter, _ *http.Request) {
	h.entered <- struct{}{}
	<-h.release
	w.Write([]byte("metrics"))
}

// awaitEntered waits for one request to reach h, and fails the test rather
// than blocking forever if the limiter never lets one through.
func awaitEntered(t *testing.T, h *blockingHandler) {
	t.Helper()
	select {
	case <-h.entered:
	case <-time.After(waitTimeout):
		t.Fatal("timed out waiting for a request to reach the metrics handler")
	}
}

// awaitDone waits for the in-flight requests tracked by wg to return, and
// fails the test rather than blocking forever if one of them never does.
func awaitDone(t *testing.T, wg *sync.WaitGroup) {
	t.Helper()
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(waitTimeout):
		t.Fatal("timed out waiting for in-flight requests to return")
	}
}

// runnerForMaxRequests builds a server whose metrics path is served by handler,
// with --web.max-requests set to the given value. Logs go to logs when it is
// not nil, and are discarded otherwise.
func runnerForMaxRequests(t *testing.T, handler http.Handler, logs *bytes.Buffer, args ...string) *http.Server {
	t.Helper()
	if logs == nil {
		logs = &bytes.Buffer{}
	}
	tk := New(Config{
		App:            kingpin.New("test", ""),
		Name:           "test_exporter",
		DefaultAddress: ":0",
		Logger:         slog.New(slog.NewTextHandler(logs, nil)),
		MetricsHandler: handler,
	})
	if err := tk.parse(args); err != nil {
		t.Fatalf("parse: %v", err)
	}
	metricsHandler, err := tk.resolveMetricsHandler()
	if err != nil {
		t.Fatalf("resolveMetricsHandler: %v", err)
	}
	server, err := tk.newServer(metricsHandler)
	if err != nil {
		t.Fatalf("newServer: %v", err)
	}
	return server
}

// runnerForFactory builds a server whose routes come from factory, with
// --web.max-requests set to the given value.
func runnerForFactory(t *testing.T, factory MetricsHandlerFactory, args ...string) *http.Server {
	t.Helper()
	tk := New(Config{
		App:                   kingpin.New("test", ""),
		Name:                  "test_exporter",
		DefaultAddress:        ":0",
		MetricsHandlerFactory: factory,
	})
	if err := tk.parse(args); err != nil {
		t.Fatalf("parse: %v", err)
	}
	handler, err := tk.resolveMetricsHandler()
	if err != nil {
		t.Fatalf("resolveMetricsHandler: %v", err)
	}
	server, err := tk.newServer(handler)
	if err != nil {
		t.Fatalf("newServer: %v", err)
	}
	return server
}

// TestMaxRequestsLimitsParallelScrapes checks that --web.max-requests bounds
// the number of scrapes served at once and answers the rest with 503.
func TestMaxRequestsLimitsParallelScrapes(t *testing.T) {
	handler := newBlockingHandler(2)
	logs := &bytes.Buffer{}
	server := runnerForMaxRequests(t, handler, logs, "--web.max-requests=1")

	// Occupy the single slot and wait until the handler is actually running.
	var wg sync.WaitGroup
	wg.Go(func() {
		rec := httptest.NewRecorder()
		server.Handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))
		if rec.Code != http.StatusOK {
			t.Errorf("first request: got status %d, expected %d", rec.Code, http.StatusOK)
		}
	})
	awaitEntered(t, handler)

	rec := httptest.NewRecorder()
	server.Handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	if rec.Code != http.StatusServiceUnavailable {
		t.Errorf("second request: got status %d, expected %d", rec.Code, http.StatusServiceUnavailable)
	}

	rec = httptest.NewRecorder()
	server.Handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	if rec.Code != http.StatusServiceUnavailable {
		t.Errorf("third request: got status %d, expected %d", rec.Code, http.StatusServiceUnavailable)
	}

	// Rejected scrapes never reach the exporter's handler, so the log line is
	// the only place they are reported, and a burst is collapsed into one.
	if got := strings.Count(logs.String(), "limit of concurrent requests reached"); got != 1 {
		t.Errorf("got %d log lines about rejected scrapes, expected 1: %q", got, logs.String())
	}

	close(handler.release)
	awaitDone(t, &wg)

	// The same server serves a scrape again, so the slot was released.
	rec = httptest.NewRecorder()
	server.Handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	if rec.Code != http.StatusOK {
		t.Errorf("request after release: got status %d, expected %d", rec.Code, http.StatusOK)
	}
}

// TestMaxRequestsZeroDisablesTheLimit checks that 0 means unlimited, as the
// flag help says.
func TestMaxRequestsZeroDisablesTheLimit(t *testing.T) {
	handler := newBlockingHandler(4)
	server := runnerForMaxRequests(t, handler, nil, "--web.max-requests=0")

	const parallel = 3
	var wg sync.WaitGroup
	for range parallel {
		wg.Go(func() {
			rec := httptest.NewRecorder()
			server.Handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))
			if rec.Code != http.StatusOK {
				t.Errorf("got status %d, expected %d", rec.Code, http.StatusOK)
			}
		})
	}
	// All of them must get into the handler at the same time.
	for range parallel {
		awaitEntered(t, handler)
	}
	close(handler.release)
	awaitDone(t, &wg)
}

// TestMaxRequestsBoundsOptedInRoutes checks which routes --web.max-requests
// bounds: the metrics endpoint always, and any other route wrapped in
// Bootstrap.MaxRequestsHandler. A route that doesn't opt in, like /healthz,
// stays responsive regardless of which route is saturated.
func TestMaxRequestsBoundsOptedInRoutes(t *testing.T) {
	for _, tc := range []struct {
		name   string
		target string // the route to saturate and expect a 503 from.
	}{
		{name: "metrics endpoint is bound by default", target: "/metrics"},
		{name: "route wrapped in MaxRequestsHandler is bound", target: "/probe"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			blocking := newBlockingHandler(1)
			metricsHandler := http.Handler(blocking)
			if tc.target != "/metrics" {
				metricsHandler = http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
					w.WriteHeader(http.StatusOK)
				})
			}
			server := runnerForFactory(t, func(b *Bootstrap) (http.Handler, error) {
				if tc.target == "/probe" {
					b.Handle("/probe", b.MaxRequestsHandler(blocking))
				}
				b.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
					w.Write([]byte("ok"))
				})
				return metricsHandler, nil
			}, "--web.max-requests=1")

			var wg sync.WaitGroup
			wg.Go(func() {
				server.Handler.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, tc.target, nil))
			})
			awaitEntered(t, blocking)

			rec := httptest.NewRecorder()
			server.Handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, tc.target, nil))
			if rec.Code != http.StatusServiceUnavailable {
				t.Errorf("second request to %s: got status %d, expected %d", tc.target, rec.Code, http.StatusServiceUnavailable)
			}

			// /healthz never opted in, so it stays responsive.
			rec = httptest.NewRecorder()
			server.Handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/healthz", nil))
			if rec.Code != http.StatusOK {
				t.Errorf("/healthz while %s is saturated: got status %d, expected %d", tc.target, rec.Code, http.StatusOK)
			}

			close(blocking.release)
			awaitDone(t, &wg)
		})
	}
}
