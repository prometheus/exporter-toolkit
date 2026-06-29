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
	"strings"
	"testing"

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
