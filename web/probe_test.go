// Copyright 2026 The Prometheus Authors
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
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestProbeListenerDisabled(t *testing.T) {
	mainPort := getPort()
	probePort := getPort()

	metricsHits := atomic.Int32{}
	server := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/metrics" {
				metricsHits.Add(1)
			}
			w.WriteHeader(http.StatusOK)
		}),
	}

	runListenAndServe(t, server, &FlagConfig{
		WebListenAddresses: &[]string{mainPort},
		WebSystemdSocket:   new(false),
		WebConfigFile:      new(""),
	})

	waitForPort(t, mainPort)

	_, err := net.DialTimeout("tcp", "127.0.0.1"+probePort, 200*time.Millisecond)
	if err == nil {
		t.Fatalf("expected probe port %s to be closed", probePort)
	}

	resp, err := http.Get("http://127.0.0.1" + mainPort + "/metrics")
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if metricsHits.Load() != 1 {
		t.Fatalf("expected metrics handler to be called once, got %d", metricsHits.Load())
	}
}

func TestProbeListenerPlainHTTPAllowlist(t *testing.T) {
	mainPort := getPort()
	probePort := getPort()

	metricsHits := atomic.Int32{}
	healthBody := "ok"
	server := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch r.URL.Path {
			case "/metrics":
				metricsHits.Add(1)
				w.WriteHeader(http.StatusOK)
			case "/-/healthy":
				_, _ = w.Write([]byte(healthBody))
			default:
				http.NotFound(w, r)
			}
		}),
	}

	runListenAndServe(t, server, &FlagConfig{
		WebListenAddresses:    &[]string{mainPort},
		WebSystemdSocket:      new(false),
		WebConfigFile:         new("testdata/web_config_users_noTLS.good.yml"),
		WebProbeListenAddress: new(probePort),
		Probe: &ProbeConfig{
			AllowedPaths: []string{"/-/healthy"},
			Handler:      server.Handler,
		},
	})

	waitForPort(t, mainPort)
	waitForPort(t, probePort)

	unauth, err := http.Get("http://127.0.0.1" + mainPort + "/-/healthy")
	if err != nil {
		t.Fatal(err)
	}
	_ = unauth.Body.Close()
	if unauth.StatusCode != http.StatusUnauthorized {
		t.Fatalf("main listener expected 401, got %d", unauth.StatusCode)
	}

	probeResp, err := http.Get("http://127.0.0.1" + probePort + "/-/healthy")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(probeResp.Body)
	_ = probeResp.Body.Close()
	if probeResp.StatusCode != http.StatusOK || string(body) != healthBody {
		t.Fatalf("probe healthy: status=%d body=%q", probeResp.StatusCode, body)
	}

	for _, path := range []string{"/metrics", "/debug/pprof/", "/%2e%2e/metrics"} {
		resp, err := http.Get("http://127.0.0.1" + probePort + path)
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusNotFound {
			t.Fatalf("path %s: expected 404, got %d", path, resp.StatusCode)
		}
	}
	if metricsHits.Load() != 0 {
		t.Fatalf("metrics handler should not run on probe port, got %d calls", metricsHits.Load())
	}
}

func TestProbeListenerWithTLSMain(t *testing.T) {
	mainPort := getPort()
	probePort := getPort()

	server := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/-/healthy" {
				w.WriteHeader(http.StatusOK)
				return
			}
			http.NotFound(w, r)
		}),
	}

	runListenAndServe(t, server, &FlagConfig{
		WebListenAddresses:    &[]string{mainPort},
		WebSystemdSocket:      new(false),
		WebConfigFile:         new("testdata/web_config_noAuth.good.yml"),
		WebProbeListenAddress: new(probePort),
		Probe: &ProbeConfig{
			AllowedPaths: []string{"/-/healthy"},
			Handler:      server.Handler,
		},
	})

	waitForPort(t, mainPort)
	waitForPort(t, probePort)

	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}
	mainResp, err := client.Get("https://127.0.0.1" + mainPort + "/-/healthy")
	if err != nil {
		t.Fatal(err)
	}
	_ = mainResp.Body.Close()
	if mainResp.StatusCode != http.StatusOK {
		t.Fatalf("main TLS healthy: got %d", mainResp.StatusCode)
	}

	probeResp, err := http.Get("http://127.0.0.1" + probePort + "/-/healthy")
	if err != nil {
		t.Fatal(err)
	}
	_ = probeResp.Body.Close()
	if probeResp.StatusCode != http.StatusOK {
		t.Fatalf("probe healthy: got %d", probeResp.StatusCode)
	}
}

func TestValidateProbeConfig(t *testing.T) {
	main := ":9100"
	for _, tc := range []struct {
		name    string
		flags   FlagConfig
		wantErr error
	}{
		{
			name: "probe address conflicts with main",
			flags: FlagConfig{
				WebListenAddresses:    &[]string{main},
				WebSystemdSocket:      new(false),
				WebConfigFile:         new(""),
				WebProbeListenAddress: new(main),
				Probe: &ProbeConfig{
					AllowedPaths: []string{"/-/healthy"},
					Handler:      http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}),
				},
			},
			wantErr: ErrProbeAddressInUse,
		},
		{
			name: "probe address set without configuration",
			flags: FlagConfig{
				WebListenAddresses:    &[]string{":9101"},
				WebSystemdSocket:      new(false),
				WebConfigFile:         new(""),
				WebProbeListenAddress: new(":9102"),
			},
			wantErr: ErrProbeConfigMissing,
		},
		{
			name: "vsock probe address",
			flags: FlagConfig{
				WebListenAddresses:    &[]string{":9101"},
				WebSystemdSocket:      new(false),
				WebConfigFile:         new(""),
				WebProbeListenAddress: new("vsock://:9102"),
				Probe: &ProbeConfig{
					AllowedPaths: []string{"/-/healthy"},
					Handler:      http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}),
				},
			},
			wantErr: ErrProbeVsockUnsupported,
		},
		{
			name: "allowed path is not rooted",
			flags: FlagConfig{
				WebListenAddresses:    &[]string{":9101"},
				WebSystemdSocket:      new(false),
				WebConfigFile:         new(""),
				WebProbeListenAddress: new(":9102"),
				Probe: &ProbeConfig{
					AllowedPaths: []string{"-/healthy"},
					Handler:      http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}),
				},
			},
			wantErr: ErrProbePathInvalid,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.flags.validateProbeConfig()
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("validateProbeConfig() = %v, want %v", err, tc.wantErr)
			}
		})
	}
}

func TestProbeConflictsWithMainEquivalentBind(t *testing.T) {
	for _, tc := range []struct {
		probe, main string
		want        bool
	}{
		{probe: ":9091", main: "0.0.0.0:9091", want: true},
		{probe: "[::0]:9091", main: "127.0.0.1:9091", want: true},
		{probe: "[::]:9091", main: "127.0.0.1:9091", want: true},
		{probe: "127.0.0.1:9091", main: "10.0.0.1:9091", want: false},
	} {
		if got := probeConflictsWithMain(tc.probe, tc.main); got != tc.want {
			t.Errorf("probeConflictsWithMain(%q, %q) = %v, want %v", tc.probe, tc.main, got, tc.want)
		}
	}
}

func TestListenAndServeProbeDoesNotMaskMainListenError(t *testing.T) {
	mainListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = mainListener.Close() })

	probePort := getPort()
	var probeAccepted atomic.Bool
	stopPoll := make(chan struct{})
	var pollDone sync.WaitGroup
	pollDone.Add(1)
	go func() {
		defer pollDone.Done()
		for {
			select {
			case <-stopPoll:
				return
			default:
			}
			conn, dialErr := net.DialTimeout("tcp", "127.0.0.1"+probePort, 20*time.Millisecond)
			if dialErr == nil {
				probeAccepted.Store(true)
				_ = conn.Close()
				return
			}
			time.Sleep(5 * time.Millisecond)
		}
	}()

	server := &http.Server{
		Handler: http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}),
	}
	err = ListenAndServe(server, &FlagConfig{
		WebListenAddresses:    &[]string{mainListener.Addr().String()},
		WebSystemdSocket:      new(false),
		WebConfigFile:         new(""),
		WebProbeListenAddress: new(probePort),
		Probe: &ProbeConfig{
			AllowedPaths: []string{"/-/healthy"},
			Handler:      server.Handler,
		},
	}, testlogger)
	close(stopPoll)
	pollDone.Wait()
	if probeAccepted.Load() {
		t.Fatal("probe accepted a connection although the main listener failed to bind")
	}
	if err == nil || errors.Is(err, http.ErrServerClosed) {
		t.Fatalf("ListenAndServe() = %v, want main listen error", err)
	}
}

func TestProbeStopsWhenMainServerShutsDown(t *testing.T) {
	mainPort := getPort()
	probePort := getPort()

	hold := make(chan struct{})
	var releaseOnce sync.Once
	release := func() { releaseOnce.Do(func() { close(hold) }) }
	entered := make(chan struct{})
	var enteredOnce sync.Once

	server := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/hold" {
				enteredOnce.Do(func() { close(entered) })
				<-hold
				return
			}
			w.WriteHeader(http.StatusOK)
		}),
	}
	errCh := make(chan error, 1)
	go func() {
		errCh <- ListenAndServe(server, &FlagConfig{
			WebListenAddresses:    &[]string{mainPort},
			WebSystemdSocket:      new(false),
			WebConfigFile:         new(""),
			WebProbeListenAddress: new(probePort),
			Probe: &ProbeConfig{
				AllowedPaths: []string{"/-/healthy"},
				Handler:      server.Handler,
			},
		}, testlogger)
	}()

	shutdownDone := make(chan struct{})
	t.Cleanup(func() {
		release()
		select {
		case <-shutdownDone:
		case <-time.After(5 * time.Second):
		}
	})

	waitForPort(t, mainPort)
	waitForPort(t, probePort)

	client := &http.Client{Timeout: time.Second}
	probeResp, err := client.Get("http://127.0.0.1" + probePort + "/-/healthy")
	if err != nil {
		t.Fatal(err)
	}
	_ = probeResp.Body.Close()
	if probeResp.StatusCode != http.StatusOK {
		t.Fatalf("probe healthy before shutdown: got %d", probeResp.StatusCode)
	}
	mainResp, err := client.Get("http://127.0.0.1" + mainPort + "/-/healthy")
	if err != nil {
		t.Fatal(err)
	}
	_ = mainResp.Body.Close()
	if mainResp.StatusCode != http.StatusOK {
		t.Fatalf("main healthy before shutdown: got %d", mainResp.StatusCode)
	}

	go func() {
		resp, doErr := http.Get("http://127.0.0.1" + mainPort + "/hold")
		if doErr == nil {
			_ = resp.Body.Close()
		}
	}()
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for the main request to enter the handler")
	}

	go func() {
		_ = server.Shutdown(context.Background())
		close(shutdownDone)
	}()

	deadline := time.Now().Add(5 * time.Second)
	for {
		resp, probeErr := client.Get("http://127.0.0.1" + probePort + "/-/healthy")
		if probeErr != nil || resp.StatusCode != http.StatusOK {
			if resp != nil {
				_ = resp.Body.Close()
			}
			break
		}
		_ = resp.Body.Close()
		if time.Now().After(deadline) {
			t.Fatal("probe still returned 200 while the main server was shutting down")
		}
		time.Sleep(10 * time.Millisecond)
	}

	release()
	select {
	case <-shutdownDone:
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for main server shutdown")
	}
	if err := <-errCh; err != nil && !errors.Is(err, http.ErrServerClosed) {
		t.Fatalf("ListenAndServe() = %v", err)
	}
}

// runListenAndServe starts ListenAndServe and reports a non-graceful return.
func TestServeMultipleWithProbeAllowlist(t *testing.T) {
	mainListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = mainListener.Close() })

	probePort := getPort()
	server := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/-/healthy" {
				w.WriteHeader(http.StatusOK)
				return
			}
			http.NotFound(w, r)
		}),
	}
	done := make(chan struct{})
	errCh := make(chan error, 1)
	go func() {
		errCh <- ServeMultipleWithProbe([]net.Listener{mainListener}, server, &FlagConfig{
			WebListenAddresses:    &[]string{mainListener.Addr().String()},
			WebConfigFile:         new(""),
			WebProbeListenAddress: new(probePort),
			Probe: &ProbeConfig{
				AllowedPaths: []string{"/-/healthy"},
				Handler:      server.Handler,
			},
		}, testlogger)
		close(done)
	}()
	t.Cleanup(func() {
		_ = server.Shutdown(context.Background())
		<-done
		if serveErr := <-errCh; serveErr != nil && !errors.Is(serveErr, http.ErrServerClosed) {
			t.Errorf("ServeMultipleWithProbe() = %v", serveErr)
		}
	})

	waitForPort(t, mainListener.Addr().String())
	waitForPort(t, probePort)

	health, err := http.Get("http://" + mainListener.Addr().String() + "/-/healthy")
	if err != nil {
		t.Fatal(err)
	}
	_ = health.Body.Close()
	if health.StatusCode != http.StatusOK {
		t.Fatalf("main healthy status = %d", health.StatusCode)
	}

	probeHealth, err := http.Get("http://127.0.0.1" + probePort + "/-/healthy")
	if err != nil {
		t.Fatal(err)
	}
	_ = probeHealth.Body.Close()
	if probeHealth.StatusCode != http.StatusOK {
		t.Fatalf("probe healthy status = %d", probeHealth.StatusCode)
	}

	probeMetrics, err := http.Get("http://127.0.0.1" + probePort + "/metrics")
	if err != nil {
		t.Fatal(err)
	}
	_ = probeMetrics.Body.Close()
	if probeMetrics.StatusCode != http.StatusNotFound {
		t.Fatalf("probe metrics status = %d, want 404", probeMetrics.StatusCode)
	}
}

func runListenAndServe(t *testing.T, server *http.Server, flags *FlagConfig) {
	t.Helper()
	done := make(chan struct{})
	errCh := make(chan error, 1)
	go func() {
		errCh <- ListenAndServe(server, flags, testlogger)
		close(done)
	}()
	t.Cleanup(func() {
		_ = server.Shutdown(context.Background())
		<-done
		if err := <-errCh; err != nil && !errors.Is(err, http.ErrServerClosed) {
			t.Errorf("ListenAndServe() = %v", err)
		}
	})
}
