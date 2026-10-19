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
	"net"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/coreos/go-systemd/v22/daemon"
)

func setupNotifySocket(t *testing.T) *net.UnixConn {
	t.Helper()
	tmpDir, err := os.MkdirTemp("/tmp", "notify")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	t.Cleanup(func() {
		_ = os.RemoveAll(tmpDir)
	})
	sockPath := filepath.Join(tmpDir, "notify.sock")
	addr := &net.UnixAddr{Name: sockPath, Net: "unixgram"}
	conn, err := net.ListenUnixgram("unixgram", addr)
	if err != nil {
		t.Fatalf("failed to listen on unixgram socket: %v", err)
	}
	t.Cleanup(func() {
		conn.Close()
	})
	t.Setenv("NOTIFY_SOCKET", sockPath)
	return conn
}

func TestSdNotifyReadiness_Success(t *testing.T) {
	conn := setupNotifySocket(t)

	server := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Write([]byte("OK"))
		}),
	}

	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}
	defer l.Close()

	emptyConfig := ""
	flags := FlagConfig{
		WebConfigFile: &emptyConfig,
	}

	errCh := make(chan error, 1)
	go func() {
		errCh <- Serve(l, server, &flags, testlogger)
	}()

	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 1024)
	n, _, err := conn.ReadFrom(buf)
	if err != nil {
		t.Fatalf("expected to receive readiness notification on NOTIFY_SOCKET, got: %v", err)
	}

	msg := string(buf[:n])
	if msg != daemon.SdNotifyReady {
		t.Fatalf("expected notification %q, got %q", daemon.SdNotifyReady, msg)
	}

	_ = server.Close()
	<-errCh
}

func TestSdNotifyReadiness_SuccessWithTLS(t *testing.T) {
	conn := setupNotifySocket(t)

	server := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Write([]byte("OK"))
		}),
	}

	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}
	defer l.Close()

	configFile := "testdata/web_config_noAuth.good.yml"
	flags := FlagConfig{
		WebConfigFile: &configFile,
	}

	errCh := make(chan error, 1)
	go func() {
		errCh <- Serve(l, server, &flags, testlogger)
	}()

	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 1024)
	n, _, err := conn.ReadFrom(buf)
	if err != nil {
		t.Fatalf("expected to receive readiness notification on NOTIFY_SOCKET, got: %v", err)
	}

	msg := string(buf[:n])
	if msg != daemon.SdNotifyReady {
		t.Fatalf("expected notification %q, got %q", daemon.SdNotifyReady, msg)
	}

	_ = server.Close()
	<-errCh
}

func TestSdNotifyReadiness_ServeMultiple(t *testing.T) {
	conn := setupNotifySocket(t)

	server := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Write([]byte("OK"))
		}),
	}

	l1, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen on l1: %v", err)
	}
	defer l1.Close()

	l2, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen on l2: %v", err)
	}
	defer l2.Close()

	configFile := "testdata/web_config_noAuth.good.yml"
	flags := FlagConfig{
		WebConfigFile: &configFile,
	}

	errCh := make(chan error, 1)
	go func() {
		errCh <- ServeMultiple([]net.Listener{l1, l2}, server, &flags, testlogger)
	}()

	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 1024)
	n, _, err := conn.ReadFrom(buf)
	if err != nil {
		t.Fatalf("expected to receive readiness notification on NOTIFY_SOCKET, got: %v", err)
	}

	msg := string(buf[:n])
	if msg != daemon.SdNotifyReady {
		t.Fatalf("expected notification %q, got %q", daemon.SdNotifyReady, msg)
	}

	_ = server.Close()
	<-errCh
}

func TestSdNotifyReadiness_Failure(t *testing.T) {
	testCases := []struct {
		name       string
		configFile string
	}{
		{
			name:       "invalid YAML",
			configFile: "testdata/web_config_junk.yml",
		},
		{
			name:       "nonexistent file",
			configFile: "testdata/nonexistent.yml",
		},
		{
			name:       "invalid cert path",
			configFile: "testdata/web_config_noAuth_certPath_invalid.bad.yml",
		},
		{
			name:       "invalid client CA without auth policy",
			configFile: "testdata/web_config_auth_clientCAs_invalid.bad.yml",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			conn := setupNotifySocket(t)

			server := &http.Server{}
			l, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatalf("failed to listen: %v", err)
			}
			defer l.Close()

			flags := FlagConfig{
				WebConfigFile: &tc.configFile,
			}

			err = Serve(l, server, &flags, testlogger)
			if err == nil {
				t.Fatalf("expected initialization error, got nil")
			}

			// Verify that READY=1 was NOT sent.
			_ = conn.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
			buf := make([]byte, 1024)
			n, _, readErr := conn.ReadFrom(buf)
			if readErr == nil {
				t.Fatalf("expected no notification on failure, received: %q", string(buf[:n]))
			}
		})
	}
}
