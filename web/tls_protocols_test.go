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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"go/build"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"
)

func TestTLSNextProtosPreservesConfig(t *testing.T) {
	original := []string{"acme-tls/1", "h2", "http/1.1"}
	server := &http.Server{
		TLSConfig: &tls.Config{NextProtos: slices.Clone(original)},
		Protocols: new(http.Protocols),
	}
	server.Protocols.SetHTTP1(true)
	got := tlsNextProtos(server, false)
	if want := []string{"acme-tls/1", "http/1.1"}; !slices.Equal(got, want) {
		t.Fatalf("protocols = %v, want %v", got, want)
	}
	// Filtering and subsequently using a returned config must not mutate the
	// original list shared with ServeTLS or another connection's callback.
	got[0] = "changed"
	if !slices.Equal(server.TLSConfig.NextProtos, original) {
		t.Errorf("original protocols changed to %v", server.TLSConfig.NextProtos)
	}
}

func TestServeTLSProtocols(t *testing.T) {
	protocols := func(http1, http2, unencryptedHTTP2 bool) *http.Protocols {
		p := new(http.Protocols)
		p.SetHTTP1(http1)
		p.SetHTTP2(http2)
		p.SetUnencryptedHTTP2(unencryptedHTTP2)
		return p
	}
	customHTTP2 := map[string]func(*http.Server, *tls.Conn, http.Handler){
		"h2": func(_ *http.Server, conn *tls.Conn, _ http.Handler) { conn.Close() },
	}
	// Go 1.27 defaults an empty explicit protocol set to HTTP/1. Earlier
	// supported toolchains leave all protocols disabled.
	emptyProtocolsWant := ""
	if slices.Contains(build.Default.ReleaseTags, "go1.27") {
		emptyProtocolsWant = "http/1.1"
	}
	tests := []struct {
		name         string
		disableHTTP2 bool
		goDebug      string
		protocols    *http.Protocols
		nextProto    map[string]func(*http.Server, *tls.Conn, http.Handler)
		clientProtos []string
		want         string
	}{
		{name: "default", want: "h2"},
		{name: "http1 client", clientProtos: []string{"http/1.1"}, want: "http/1.1"},
		{name: "web config disables http2", disableHTTP2: true, want: "http/1.1"},
		{name: "GODEBUG disables http2", goDebug: "http2server=0", want: "http/1.1"},
		{name: "legacy http2 disablement", nextProto: map[string]func(*http.Server, *tls.Conn, http.Handler){}, want: "http/1.1"},
		{name: "explicit http1", protocols: protocols(true, false, false), want: "http/1.1"},
		{name: "explicit http2", protocols: protocols(false, true, false), want: "h2"},
		{name: "explicit http1 and http2", protocols: protocols(true, true, false), want: "h2"},
		{name: "http2 only does not advertise http1", protocols: protocols(false, true, false), clientProtos: []string{"http/1.1"}},
		{name: "unencrypted http2 does not enable TLS http2", protocols: protocols(true, false, true), want: "http/1.1"},
		{name: "unencrypted http2 only", protocols: protocols(false, false, true)},
		{name: "empty explicit protocols", protocols: new(http.Protocols), want: emptyProtocolsWant},
		{name: "web config overrides explicit http2", protocols: protocols(true, true, false), disableHTTP2: true, want: "http/1.1"},
		{name: "GODEBUG overrides explicit http2", protocols: protocols(true, true, false), goDebug: "http2server=0", want: "http/1.1"},
		{name: "explicit protocols override legacy disablement", protocols: protocols(true, true, false), nextProto: map[string]func(*http.Server, *tls.Conn, http.Handler){}, want: "h2"},
		{name: "custom http2", nextProto: customHTTP2, want: "h2"},
		{name: "GODEBUG preserves custom http2", nextProto: customHTTP2, goDebug: "http2server=0", want: "h2"},
		{name: "web config disables custom http2", nextProto: customHTTP2, disableHTTP2: true, want: "http/1.1"},
		{name: "explicit protocols disable custom http2", nextProto: customHTTP2, protocols: protocols(true, false, false), want: "http/1.1"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			debug := "http2server=1"
			if tc.goDebug != "" {
				debug = tc.goDebug
			}
			t.Setenv("GODEBUG", os.Getenv("GODEBUG")+","+debug)
			dir, err := filepath.Abs("testdata")
			if err != nil {
				t.Fatal(err)
			}
			configPath := filepath.Join(t.TempDir(), "web.yml")
			config := fmt.Sprintf("tls_server_config:\n  cert_file: %q\n  key_file: %q\nhttp_server_config:\n  http2: %t\n", filepath.Join(dir, "server.crt"), filepath.Join(dir, "server.key"), !tc.disableHTTP2)
			if err := os.WriteFile(configPath, []byte(config), 0600); err != nil {
				t.Fatal(err)
			}
			server := &http.Server{Protocols: tc.protocols, TLSNextProto: tc.nextProto}
			address := startTLSProtocolServer(t, server, configPath)
			clientConfig := getTLSClient("").Transport.(*http.Transport).TLSClientConfig
			clientConfig.ServerName = "localhost"
			clientConfig.NextProtos = tc.clientProtos
			if clientConfig.NextProtos == nil {
				clientConfig.NextProtos = []string{"h2", "http/1.1"}
			}
			conn, err := tls.DialWithDialer(&net.Dialer{Timeout: 5 * time.Second}, "tcp", address, clientConfig)
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			if got := conn.ConnectionState().NegotiatedProtocol; got != tc.want {
				t.Errorf("negotiated protocol = %q, want %q", got, tc.want)
			}
		})
	}
}

func startTLSProtocolServer(t *testing.T, server *http.Server, configPath string) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		done <- Serve(listener, server, &FlagConfig{WebConfigFile: &configPath}, testlogger)
	}()
	t.Cleanup(func() {
		server.Close()
		listener.Close()
		select {
		case err := <-done:
			if err != nil && !errors.Is(err, http.ErrServerClosed) && !errors.Is(err, net.ErrClosed) {
				t.Errorf("Serve: %v", err)
			}
		case <-time.After(5 * time.Second):
			t.Error("Serve did not stop")
		}
	})
	return listener.Addr().String()
}

func TestServeTLSProtocolsAfterReload(t *testing.T) {
	t.Setenv("GODEBUG", os.Getenv("GODEBUG")+",http2server=1")
	cert1, certPEM1, keyPEM1 := tlsProtocolCertificate(t, 1)
	cert2, certPEM2, keyPEM2 := tlsProtocolCertificate(t, 2)
	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM(certPEM1)
	roots.AppendCertsFromPEM(certPEM2)
	dir := t.TempDir()
	write := func(name string, data []byte) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(dir, name), data, 0600); err != nil {
			t.Fatal(err)
		}
	}
	write("server.crt", certPEM1)
	write("server.key", keyPEM1)
	write("client-ca.crt", certPEM1)
	write("web.yml", []byte("tls_server_config:\n  cert_file: server.crt\n  key_file: server.key\n  client_ca_file: client-ca.crt\n  client_auth_type: RequireAndVerifyClientCert\n"))
	server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Write([]byte("ok"))
	})}
	address := startTLSProtocolServer(t, server, filepath.Join(dir, "web.yml"))
	request := func(cert tls.Certificate, serial int64) error {
		transport := &http.Transport{
			ForceAttemptHTTP2: true,
			TLSClientConfig: &tls.Config{
				RootCAs: roots, ServerName: "localhost",
				// Send the requested certificate even if its issuer is absent from
				// the server's advertised CAs, so rejection tests CA verification.
				GetClientCertificate: func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
					return &cert, nil
				},
			},
		}
		defer transport.CloseIdleConnections()
		client := &http.Client{Transport: transport, Timeout: 5 * time.Second}
		resp, err := client.Get("https://" + address)
		if err != nil {
			return err
		}
		defer resp.Body.Close()
		if _, err := io.Copy(io.Discard, resp.Body); err != nil {
			return err
		}
		if resp.ProtoMajor != 2 || resp.TLS.NegotiatedProtocol != "h2" {
			return fmt.Errorf("protocol = %s, ALPN = %q; want HTTP/2 with h2", resp.Proto, resp.TLS.NegotiatedProtocol)
		}
		if got := resp.TLS.PeerCertificates[0].SerialNumber.Int64(); got != serial {
			return fmt.Errorf("server certificate serial = %d, want %d", got, serial)
		}
		return nil
	}
	checkConnections := func(cert tls.Certificate, serial int64) {
		t.Helper()
		errs := make(chan error, 8)
		for range cap(errs) {
			go func() { errs <- request(cert, serial) }()
		}
		for range cap(errs) {
			if err := <-errs; err != nil {
				t.Error(err)
			}
		}
	}
	checkConnections(cert1, 1)
	write("server.crt", certPEM2)
	write("server.key", keyPEM2)
	write("client-ca.crt", certPEM2)
	checkConnections(cert2, 2)
	if err := request(cert1, 2); err == nil {
		t.Error("client signed by the previous CA was accepted after reload")
	}
}

func tlsProtocolCertificate(t *testing.T, serial int64) (tls.Certificate, []byte, []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: fmt.Sprintf("test-%d", serial)},
		DNSNames: []string{"localhost"}, NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	return cert, certPEM, keyPEM
}
