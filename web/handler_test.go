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
	"net/http"
	"sync"
	"testing"
)

// TestBasicAuthCache validates that the cache is working by calling a password
// protected endpoint multiple times.
func TestBasicAuthCache(t *testing.T) {
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
			WebConfigFile:      OfString("testdata/web_config_users_noTLS.good.yml"),
		}
		ListenAndServe(server, &flags, testlogger)
		close(done)
	}()

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
	wg.Add(300)
	for i := 0; i < 150; i++ {
		go func() {
			<-start
			login("alice", "alice123", 200)
			wg.Done()
		}()
		go func() {
			<-start
			login("alice", "alice1234", 401)
			wg.Done()
		}()
	}
	close(start)
	wg.Wait()
}

// TestBasicAuthWithFakePassword validates that we can't login the "fakepassword" used in
// to prevent user enumeration.
func TestBasicAuthWithFakepassword(t *testing.T) {
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
			WebConfigFile:      OfString("testdata/web_config_users_noTLS.good.yml"),
		}
		ListenAndServe(server, &flags, testlogger)
		close(done)
	}()

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
