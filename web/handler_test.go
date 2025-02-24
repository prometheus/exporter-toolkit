// Copyright 2021 The Prometheus Authors
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
	"net"
	"net/http"
	"testing"
	"time"
)

// TestHTTPHeaders validates that HTTP headers are added correctly.
func TestHTTPHeaders(t *testing.T) {
	server := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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
			WebConfigFile:      OfString("testdata/web_config_headers.good.yml"),
		}
		ListenAndServe(server, &flags, testlogger)
		close(done)
	}()

	waitForPort(t, port)

	client := &http.Client{}
	req, err := http.NewRequest("GET", "http://localhost"+port, nil)
	if err != nil {
		t.Fatal(err)
	}
	r, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}

	for k, v := range map[string]string{
		"Strict-Transport-Security": "max-age=31536000; includeSubDomains",
		"X-Frame-Options":           "deny",
		"X-Content-Type-Options":    "nosniff",
		"X-XSS-Protection":          "1",
	} {
		if got := r.Header.Get(k); got != v {
			t.Fatalf("unexpected %s header value, expected %q, got %q", k, v, got)
		}
	}
}

func waitForPort(t *testing.T, addr string) {
	start := time.Now()
	for {
		conn, err := net.DialTimeout("tcp", addr, time.Second)
		if err == nil {
			conn.Close()
			return
		}
		if time.Since(start) >= 5*time.Second {
			t.Fatalf("timeout waiting for port %s: %s", addr, err)
			return
		}
		time.Sleep(time.Millisecond * 100)
	}
}
