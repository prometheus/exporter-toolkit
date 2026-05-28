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
	"sync"
	"testing"
	"time"
)

// handlerCase is one row in the TestHandler table. Each case starts an HTTP
// server with the named YAML config and then runs `do` against it. The
// per-case `do` function holds the assertions specific to that case; the
// shared server lifecycle (start, wait, shutdown) is provided by
// withHandlerServer so it doesn't have to be duplicated per case.
type handlerCase struct {
	name           string
	yamlConfigPath string
	do             func(t *testing.T)
}

func TestHandler(t *testing.T) {
	cases := []handlerCase{
		{
			name:           "BasicAuthCache",
			yamlConfigPath: "testdata/web_config_users_noTLS.good.yml",
			do:             testBasicAuthCacheBody,
		},
		{
			name:           "BasicAuthWithFakepassword",
			yamlConfigPath: "testdata/web_config_users_noTLS.good.yml",
			do:             testBasicAuthFakepasswordBody,
		},
		{
			name:           "ByPassBasicAuthVuln",
			yamlConfigPath: "testdata/web_config_users_noTLS.good.yml",
			do:             testByPassBasicAuthVulnBody,
		},
		{
			name:           "HTTPHeaders",
			yamlConfigPath: "testdata/web_config_headers.good.yml",
			do:             testHTTPHeadersBody,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			withHandlerServer(t, tc.yamlConfigPath, tc.do)
		})
	}
}

// withHandlerServer starts an http.Server on the package-level `port` using
// the given YAML config, waits until the port is reachable, runs body, and
// then shuts the server down. Replaces the per-test boilerplate that the
// original four separate test functions duplicated.
func withHandlerServer(t *testing.T, yamlConfigPath string, body func(t *testing.T)) {
	t.Helper()
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
			WebConfigFile:      OfString(yamlConfigPath),
		}
		ListenAndServe(server, &flags, testlogger)
		close(done)
	}()
	waitForPort(t, port)
	body(t)
}

// testBasicAuthCacheBody validates that the cache is working by calling a
// password-protected endpoint repeatedly, then stressing it concurrently.
func testBasicAuthCacheBody(t *testing.T) {
	login := func(username, password string, code int) {
		client := &http.Client{}
		req, err := http.NewRequest("GET", "http://localhost"+port, nil)
		if err != nil {
			t.Fatal(err)
		}
		req.SetBasicAuth(username, password)
		r, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		if r.StatusCode != code {
			t.Fatalf("bad return code, expected %d, got %d", code, r.StatusCode)
		}
	}

	// Initial logins, checking that it just works.
	login("alice", "alice123", 200)
	login("alice", "alice1234", 401)

	var (
		start = make(chan struct{})
		wg    sync.WaitGroup
	)
	for range 150 {
		wg.Go(func() {
			<-start
			login("alice", "alice123", 200)
		})
		wg.Go(func() {
			<-start
			login("alice", "alice1234", 401)
		})
	}
	close(start)
	wg.Wait()
}

// testBasicAuthFakepasswordBody validates that we can't login with the
// "fakepassword" used to prevent user enumeration.
func testBasicAuthFakepasswordBody(t *testing.T) {
	login := func() {
		client := &http.Client{}
		req, err := http.NewRequest("GET", "http://localhost"+port, nil)
		if err != nil {
			t.Fatal(err)
		}
		req.SetBasicAuth("fakeuser", "fakepassword")
		r, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		if r.StatusCode != 401 {
			t.Fatalf("bad return code, expected %d, got %d", 401, r.StatusCode)
		}
	}
	// Login with a cold cache.
	login()
	// Login with the response cached.
	login()
}

// testByPassBasicAuthVulnBody tests for CVE-2022-46146.
func testByPassBasicAuthVulnBody(t *testing.T) {
	login := func(username, password string) {
		client := &http.Client{}
		req, err := http.NewRequest("GET", "http://localhost"+port, nil)
		if err != nil {
			t.Fatal(err)
		}
		req.SetBasicAuth(username, password)
		r, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		if r.StatusCode != 401 {
			t.Fatalf("bad return code, expected %d, got %d", 401, r.StatusCode)
		}
	}
	// Poison the cache.
	login("alice$2y$12$1DpfPeqF9HzHJt.EWswy1exHluGfbhnn3yXhR7Xes6m3WJqFg0Wby", "fakepassword")
	// Login with a wrong password.
	login("alice", "$2y$10$QOauhQNbBCuQDKes6eFzPeMqBSjb7Mr5DUmpZ/VcEd00UAV/LDeSifakepassword")
}

// testHTTPHeadersBody validates that HTTP headers from web_config_headers.good.yml
// are added correctly to responses.
func testHTTPHeadersBody(t *testing.T) {
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
