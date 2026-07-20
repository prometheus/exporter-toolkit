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
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/alecthomas/kingpin/v2"
	"github.com/prometheus/common/promslog"
)

func TestParseRejectsNegativeMaxRequests(t *testing.T) {
	tk := New(Config{
		App:            kingpin.New("test", ""),
		DefaultAddress: ":9100",
		Logger:         promslog.NewNopLogger(),
		MetricsHandler: http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}),
	})

	err := tk.parse([]string{"--web.max-requests=-1", "--web.listen-address=:9100"})
	if err == nil {
		t.Fatal("expected error, got nil")
	}
}

func TestResolveMetricsHandlerRejectsMultipleSources(t *testing.T) {
	tk := New(Config{
		App:            kingpin.New("test", ""),
		DefaultAddress: ":9100",
		Logger:         promslog.NewNopLogger(),
		MetricsHandler: http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}),
		MetricsHandlerFactory: func(*Bootstrap) (http.Handler, error) {
			return http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}), nil
		},
	})

	if err := tk.parse([]string{"--web.listen-address=:9100"}); err != nil {
		t.Fatalf("unexpected parse error: %v", err)
	}
	if _, err := tk.resolveMetricsHandler(); err != errMultipleMetricsSource {
		t.Fatalf("unexpected error: got %v, want %v", err, errMultipleMetricsSource)
	}
}

func TestResolveMetricsHandlerFactoryReceivesParsedBootstrap(t *testing.T) {
	var got Bootstrap
	tk := New(Config{
		App:            kingpin.New("test", ""),
		DefaultAddress: ":9100",
		Logger:         promslog.NewNopLogger(),
		MetricsHandlerFactory: func(b *Bootstrap) (http.Handler, error) {
			got = *b
			return http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}), nil
		},
	})

	if err := tk.parse([]string{"--web.max-requests=7", "--web.disable-exporter-metrics", "--web.listen-address=:9100"}); err != nil {
		t.Fatalf("unexpected parse error: %v", err)
	}
	if _, err := tk.resolveMetricsHandler(); err != nil {
		t.Fatalf("unexpected handler resolution error: %v", err)
	}
	if got.MaxRequests != 7 {
		t.Fatalf("unexpected max requests: got %d, want 7", got.MaxRequests)
	}
	if !got.DisableExporterMetrics {
		t.Fatal("expected disable exporter metrics to be true")
	}
	if got.MetricsPath != "/metrics" {
		t.Fatalf("unexpected metrics path: got %q, want %q", got.MetricsPath, "/metrics")
	}
}

func TestNewServerRegistersMetricsAndLandingPage(t *testing.T) {
	tk := New(Config{
		App:            kingpin.New("test", ""),
		Name:           "test_exporter",
		Description:    "test description",
		DefaultAddress: ":9100",
		Logger:         promslog.NewNopLogger(),
		MetricsHandler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write([]byte("metrics body"))
		}),
	})

	if err := tk.parse([]string{"--web.listen-address=:9100"}); err != nil {
		t.Fatalf("unexpected parse error: %v", err)
	}
	handler, err := tk.resolveMetricsHandler()
	if err != nil {
		t.Fatalf("unexpected handler resolution error: %v", err)
	}
	server, err := tk.newServer(handler)
	if err != nil {
		t.Fatalf("unexpected server creation error: %v", err)
	}

	metricsReq := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	metricsRec := httptest.NewRecorder()
	server.Handler.ServeHTTP(metricsRec, metricsReq)
	if metricsRec.Code != http.StatusOK {
		t.Fatalf("unexpected metrics status: got %d, want %d", metricsRec.Code, http.StatusOK)
	}
	if body := metricsRec.Body.String(); body != "metrics body" {
		t.Fatalf("unexpected metrics body: got %q", body)
	}

	landingReq := httptest.NewRequest(http.MethodGet, "/", nil)
	landingRec := httptest.NewRecorder()
	server.Handler.ServeHTTP(landingRec, landingReq)
	if landingRec.Code != http.StatusOK {
		t.Fatalf("unexpected landing status: got %d, want %d", landingRec.Code, http.StatusOK)
	}
	if body := landingRec.Body.String(); body == "" || !strings.Contains(body, "Metrics") || !strings.Contains(body, "test description") {
		t.Fatalf("unexpected landing body: %q", body)
	}
}

// TestNewServerReadHeaderTimeout checks newServer maps Config.ReadHeaderTimeout
// onto the server, defaulting to one minute when unset.
func TestNewServerReadHeaderTimeout(t *testing.T) {
	for _, tc := range []struct {
		name       string
		configured time.Duration
		want       time.Duration
	}{
		{name: "unset defaults", configured: 0, want: defaultReadHeaderTimeout},
		{name: "explicit default", configured: time.Minute, want: time.Minute},
		{name: "sub-second value", configured: 250 * time.Millisecond, want: 250 * time.Millisecond},
		{name: "smallest positive value", configured: time.Nanosecond, want: time.Nanosecond},
		{name: "large value", configured: time.Hour, want: time.Hour},
		{name: "negative defaults", configured: -1, want: defaultReadHeaderTimeout},
		{name: "large negative defaults", configured: -time.Hour, want: defaultReadHeaderTimeout},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tk := New(Config{
				App:               kingpin.New("test", ""),
				DefaultAddress:    ":9100",
				Logger:            promslog.NewNopLogger(),
				ReadHeaderTimeout: tc.configured,
				MetricsHandler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
					w.WriteHeader(http.StatusOK)
				}),
			})
			if err := tk.parse([]string{"--web.listen-address=:0"}); err != nil {
				t.Fatalf("unexpected parse error: %v", err)
			}
			handler, err := tk.resolveMetricsHandler()
			if err != nil {
				t.Fatalf("unexpected handler resolution error: %v", err)
			}
			server, err := tk.newServer(handler)
			if err != nil {
				t.Fatalf("unexpected server creation error: %v", err)
			}
			if server.ReadHeaderTimeout != tc.want {
				t.Fatalf("unexpected ReadHeaderTimeout: got %v, want %v", server.ReadHeaderTimeout, tc.want)
			}
		})
	}
}

// TestNewServerReadHeaderTimeoutClosesStalledConnection checks the timeout is
// effective end-to-end: a connection with incomplete headers is closed while a
// well-formed request succeeds.
func TestNewServerReadHeaderTimeoutClosesStalledConnection(t *testing.T) {
	const readHeaderTimeout = 250 * time.Millisecond

	tk := New(Config{
		App:               kingpin.New("test", ""),
		Name:              "test_exporter",
		Description:       "test description",
		DefaultAddress:    ":9100",
		Logger:            promslog.NewNopLogger(),
		ReadHeaderTimeout: readHeaderTimeout,
		MetricsHandler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusOK)
		}),
	})
	if err := tk.parse([]string{"--web.listen-address=:0"}); err != nil {
		t.Fatalf("unexpected parse error: %v", err)
	}
	handler, err := tk.resolveMetricsHandler()
	if err != nil {
		t.Fatalf("unexpected handler resolution error: %v", err)
	}
	server, err := tk.newServer(handler)
	if err != nil {
		t.Fatalf("unexpected server creation error: %v", err)
	}
	if server.ReadHeaderTimeout != readHeaderTimeout {
		t.Fatalf("unexpected ReadHeaderTimeout: got %v, want %v", server.ReadHeaderTimeout, readHeaderTimeout)
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() { _ = server.Serve(ln) }()
	t.Cleanup(func() { _ = server.Close() })

	// A well-formed request still succeeds.
	resp, err := http.Get("http://" + ln.Addr().String() + "/metrics")
	if err != nil {
		t.Fatalf("well-formed request failed: %v", err)
	}
	_ = resp.Body.Close()

	// Start request headers but never terminate them (no final CRLF).
	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	if _, err := conn.Write([]byte("GET /metrics HTTP/1.1\r\nHost: localhost\r\n")); err != nil {
		t.Fatalf("write partial request: %v", err)
	}

	// Read in a goroutine so the test never hangs if the server keeps it open.
	done := make(chan struct{})
	go func() {
		_, _ = conn.Read(make([]byte, 1)) // unblocks on server-side close
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("server did not close the stalled connection within 5s; ReadHeaderTimeout not effective")
	}
}
