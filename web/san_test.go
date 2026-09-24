// Copyright 2025 The Prometheus Authors
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
	"crypto/tls"
	"crypto/x509"
	"os"
	"testing"
)

// TestVerifyPeerCertificateWithoutClientCert checks that VerifyPeerCertificate
// reports a missing client certificate instead of panicking. crypto/tls calls
// it with an empty slice when the client declines to send a certificate and the
// configured client auth type does not require one.
func TestVerifyPeerCertificateWithoutClientCert(t *testing.T) {
	c := &TLSConfig{ClientAllowedSans: []string{"one"}}

	for _, tc := range []struct {
		name     string
		rawCerts [][]byte
	}{
		{name: "nil", rawCerts: nil},
		{name: "empty", rawCerts: [][]byte{}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := c.VerifyPeerCertificate(tc.rawCerts, nil)
			if err == nil {
				t.Fatal("expected an error, got nil")
			}
			if !ErrorMap["No client certificate"].MatchString(err.Error()) {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}

// TestVerifyPeerCertificateHandshakeWithoutClientCert drives a real TLS
// handshake in which the client presents no certificate, and checks that the
// server rejects it cleanly rather than panicking in the handshake goroutine.
func TestVerifyPeerCertificateHandshakeWithoutClientCert(t *testing.T) {
	cert, err := tls.LoadX509KeyPair("testdata/server.crt", "testdata/server.key")
	if err != nil {
		t.Fatalf("loading server key pair: %v", err)
	}

	tlsConfig := &TLSConfig{ClientAllowedSans: []string{"one"}}
	listener, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{cert},
		// VerifyClientCertIfGiven asks for a certificate but tolerates a
		// client that does not send one, which is what leaves rawCerts empty.
		ClientAuth:            tls.VerifyClientCertIfGiven,
		VerifyPeerCertificate: tlsConfig.VerifyPeerCertificate,
		MinVersion:            tls.VersionTLS12,
	})
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = listener.Close() })

	type result struct {
		err     error
		recover any
	}
	results := make(chan result, 1)
	go func() {
		var r result
		defer func() {
			r.recover = recover()
			results <- r
		}()
		conn, err := listener.Accept()
		if err != nil {
			r.err = err
			return
		}
		defer conn.Close()
		r.err = conn.(*tls.Conn).Handshake()
	}()

	caCert, err := os.ReadFile("testdata/tls-ca-chain.pem")
	if err != nil {
		t.Fatalf("reading CA chain: %v", err)
	}
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(caCert)

	// Under TLS 1.3 the client completes its side of the handshake before the
	// server processes the (absent) client certificate, so the dial itself may
	// succeed and only a later read would surface the server's alert. The
	// server side is what this test asserts on.
	clientConn, err := tls.Dial("tcp", listener.Addr().String(), &tls.Config{
		RootCAs:    pool,
		ServerName: "localhost",
		MinVersion: tls.VersionTLS12,
	})
	if err == nil {
		_ = clientConn.Close()
	}

	r := <-results
	if r.recover != nil {
		t.Fatalf("server panicked during the handshake: %v", r.recover)
	}
	if r.err == nil {
		t.Fatal("expected the server to reject a client that sent no certificate")
	}
	if !ErrorMap["No client certificate"].MatchString(r.err.Error()) {
		t.Fatalf("unexpected server error: %v", r.err)
	}
}
