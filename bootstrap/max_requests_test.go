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
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/alecthomas/kingpin/v2"
)

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

// runnerForMaxRequests builds a server whose metrics path is served by handler,
// with --web.max-requests set to the given value.
func runnerForMaxRequests(t *testing.T, handler http.Handler, args ...string) *http.Server {
	t.Helper()
	tk := New(Config{
		App:            kingpin.New("test", ""),
		Name:           "test_exporter",
		DefaultAddress: ":0",
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

// TestMaxRequestsLimitsParallelScrapes checks that --web.max-requests bounds
// the number of scrapes served at once and answers the rest with 503.
func TestMaxRequestsLimitsParallelScrapes(t *testing.T) {
	handler := newBlockingHandler(2)
	server := runnerForMaxRequests(t, handler, "--web.max-requests=1")

	// Occupy the single slot and wait until the handler is actually running.
	var wg sync.WaitGroup
	wg.Go(func() {
		rec := httptest.NewRecorder()
		server.Handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))
		if rec.Code != http.StatusOK {
			t.Errorf("first request: got status %d, expected %d", rec.Code, http.StatusOK)
		}
	})
	<-handler.entered

	rec := httptest.NewRecorder()
	server.Handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	if rec.Code != http.StatusServiceUnavailable {
		t.Errorf("second request: got status %d, expected %d", rec.Code, http.StatusServiceUnavailable)
	}

	close(handler.release)
	wg.Wait()

	// With the slot free again, a scrape is served.
	handler2 := newBlockingHandler(1)
	close(handler2.release)
	server2 := runnerForMaxRequests(t, handler2, "--web.max-requests=1")
	rec = httptest.NewRecorder()
	server2.Handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	if rec.Code != http.StatusOK {
		t.Errorf("request after release: got status %d, expected %d", rec.Code, http.StatusOK)
	}
}

// TestMaxRequestsZeroDisablesTheLimit checks that 0 means unlimited, as the
// flag help says.
func TestMaxRequestsZeroDisablesTheLimit(t *testing.T) {
	handler := newBlockingHandler(4)
	server := runnerForMaxRequests(t, handler, "--web.max-requests=0")

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
		<-handler.entered
	}
	close(handler.release)
	wg.Wait()
}

// TestMaxRequestsDoesNotLimitOtherRoutes checks that the bound applies to the
// metrics endpoint only, since that is what the flag describes.
func TestMaxRequestsDoesNotLimitOtherRoutes(t *testing.T) {
	metrics := newBlockingHandler(1)
	tk := New(Config{
		App:            kingpin.New("test", ""),
		Name:           "test_exporter",
		DefaultAddress: ":0",
		MetricsHandlerFactory: func(b *Bootstrap) (http.Handler, error) {
			b.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
				w.Write([]byte("ok"))
			})
			return metrics, nil
		},
	})
	if err := tk.parse([]string{"--web.max-requests=1"}); err != nil {
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

	var wg sync.WaitGroup
	wg.Go(func() {
		server.Handler.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/metrics", nil))
	})
	<-metrics.entered

	rec := httptest.NewRecorder()
	server.Handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/healthz", nil))
	if rec.Code != http.StatusOK {
		t.Errorf("/healthz while /metrics is saturated: got status %d, expected %d", rec.Code, http.StatusOK)
	}

	close(metrics.release)
	wg.Wait()
}
