// Copyright 2023 The Prometheus Authors
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

package x509

import (
	"crypto/tls"
	"crypto/x509"
	_ "embed"
	"encoding/pem"
	"errors"
	"net/http"
	"testing"

	"github.com/go-kit/log"
)

//go:embed testdata/client_selfsigned.pem
var clientSelfsignedPEM []byte

//go:embed testdata/client2_selfsigned.pem
var client2SelfsignedPEM []byte

func TestX509Authenticator_Authenticate(t *testing.T) {
	ts := []struct {
		Name string

		RequireClientCertsFn    RequireClientCertsFunc
		VerifyOptionsFn         VerifyOptionsFunc
		VerifyPeerCertificateFn VerifyPeerCertificateFunc

		Certs []*x509.Certificate

		ExpectAuthenticated bool
		ExpectedReason      string
		ExpectedError       error
	}{
		{
			Name: "Certs not required, certs not provided",
			RequireClientCertsFn: func() bool {
				return false
			},
			ExpectAuthenticated: true,
			ExpectedError:       nil,
		},
		{
			Name: "Certs required, certs not provided",
			RequireClientCertsFn: func() bool {
				return true
			},
			ExpectAuthenticated: false,
			ExpectedReason:      "A certificate is required to be sent by the client.",
			ExpectedError:       nil,
		},
		{
			Name: "Certs not required, no verify, selfsigned cert provided",
			RequireClientCertsFn: func() bool {
				return false
			},
			Certs:               getCerts(t, clientSelfsignedPEM),
			ExpectAuthenticated: true,
			ExpectedError:       nil,
		},
		{
			Name: "Certs required, no verify, selfsigned cert provided",
			RequireClientCertsFn: func() bool {
				return true
			},
			Certs:               getCerts(t, clientSelfsignedPEM),
			ExpectAuthenticated: true,
			ExpectedError:       nil,
		},
		{
			Name: "Certs not required, verify, selfsigned cert provided",
			RequireClientCertsFn: func() bool {
				return false
			},
			VerifyOptionsFn: func() x509.VerifyOptions {
				opts := DefaultVerifyOptions()
				opts.Roots = getCertPool(t, clientSelfsignedPEM)
				return opts
			},
			Certs:               getCerts(t, clientSelfsignedPEM),
			ExpectAuthenticated: true,
			ExpectedError:       nil,
		},
		{
			Name: "Certs not required, verify, no certs provided",
			RequireClientCertsFn: func() bool {
				return false
			},
			VerifyOptionsFn: func() x509.VerifyOptions {
				opts := DefaultVerifyOptions()
				opts.Roots = getCertPool(t, clientSelfsignedPEM)
				return opts
			},
			ExpectAuthenticated: true,
			ExpectedError:       nil,
		},
		{
			Name: "Certs required, verify, selfsigned cert provided",
			RequireClientCertsFn: func() bool {
				return true
			},
			VerifyOptionsFn: func() x509.VerifyOptions {
				opts := DefaultVerifyOptions()
				opts.Roots = getCertPool(t, clientSelfsignedPEM)
				return opts
			},
			Certs:               getCerts(t, clientSelfsignedPEM),
			ExpectAuthenticated: true,
			ExpectedError:       nil,
		},
		{
			Name: "Certs required, verify, invalid selfsigned cert provided",
			RequireClientCertsFn: func() bool {
				return true
			},
			VerifyOptionsFn: func() x509.VerifyOptions {
				opts := DefaultVerifyOptions()
				opts.Roots = getCertPool(t, clientSelfsignedPEM)
				return opts
			},
			Certs:               getCerts(t, client2SelfsignedPEM),
			ExpectAuthenticated: false,
			ExpectedReason: "verifying certificate SN=213094436555767319277040831510558969429548310139," +
				" SKID=BF:2B:EE:FD:39:C9:C9:14:BB:38:67:6E:8D:36:D6:33:F5:B4:EF:23," +
				" AKID=BF:2B:EE:FD:39:C9:C9:14:BB:38:67:6E:8D:36:D6:33:F5:B4:EF:23" +
				" failed: x509: certificate signed by unknown authority",
			ExpectedError: nil,
		},
		{
			Name: "Certs required, verify, selfsigned cert provided, invalid peer certificate",
			RequireClientCertsFn: func() bool {
				return true
			},
			VerifyOptionsFn: func() x509.VerifyOptions {
				opts := DefaultVerifyOptions()
				opts.Roots = getCertPool(t, clientSelfsignedPEM)
				return opts
			},
			VerifyPeerCertificateFn: func(_ [][]byte, _ [][]*x509.Certificate) error {
				return errors.New("invalid peer certificate")
			},
			Certs:               getCerts(t, clientSelfsignedPEM),
			ExpectAuthenticated: false,
			ExpectedReason:      "verifying peer certificate failed: invalid peer certificate",
			ExpectedError:       nil,
		},
		{
			Name: "RequireAndVerifyClientCert, selfsigned certs, valid peer certificate",
			RequireClientCertsFn: func() bool {
				return true
			},
			VerifyOptionsFn: func() x509.VerifyOptions {
				opts := DefaultVerifyOptions()
				opts.Roots = getCertPool(t, clientSelfsignedPEM)
				return opts
			},
			VerifyPeerCertificateFn: func(_ [][]byte, _ [][]*x509.Certificate) error {
				return nil
			},
			Certs:               getCerts(t, clientSelfsignedPEM),
			ExpectAuthenticated: true,
			ExpectedError:       nil,
		},
	}

	for _, tt := range ts {
		t.Run(tt.Name, func(t *testing.T) {
			req := makeDefaultRequest(t)
			req.TLS = &tls.ConnectionState{
				PeerCertificates: tt.Certs,
			}

			a := NewX509Authenticator(tt.RequireClientCertsFn, tt.VerifyOptionsFn, tt.VerifyPeerCertificateFn)
			authenticated, reason, err := a.Authenticate(req)

			if err != nil && tt.ExpectedError == nil {
				t.Errorf("Got unexpected error: %v", err)
			}

			if err == nil && tt.ExpectedError != nil {
				t.Errorf("Expected error %v, got none", tt.ExpectedError)
			}

			if err != nil && tt.ExpectedError != nil && !errors.Is(err, tt.ExpectedError) {
				t.Errorf("Expected error %v, got %v", tt.ExpectedError, err)
			}

			if tt.ExpectedReason != reason {
				t.Errorf("Expected reason %v, got %v", tt.ExpectedReason, reason)
			}

			if tt.ExpectAuthenticated != authenticated {
				t.Errorf("Expected authenticated %v, got %v", tt.ExpectAuthenticated, authenticated)
			}
		})
	}
}

type noOpLogger struct{}

func (noOpLogger) Log(...interface{}) error {
	return nil
}

var _ log.Logger = &noOpLogger{}

func makeDefaultRequest(t *testing.T) *http.Request {
	t.Helper()

	req, err := http.NewRequest(http.MethodGet, "/", nil)
	if err != nil {
		t.Fatalf("Error creating request: %v", err)
	}
	return req
}

func getCertPool(t *testing.T, pemData ...[]byte) *x509.CertPool {
	t.Helper()

	pool := x509.NewCertPool()
	certs := getCerts(t, pemData...)
	for _, c := range certs {
		pool.AddCert(c)
	}

	return pool
}

func getCerts(t *testing.T, pemData ...[]byte) []*x509.Certificate {
	t.Helper()

	certs := make([]*x509.Certificate, 0)
	for _, pd := range pemData {
		pemBlock, _ := pem.Decode(pd)
		cert, err := x509.ParseCertificate(pemBlock.Bytes)
		if err != nil {
			t.Fatalf("Error parsing cert: %v", err)
		}
		certs = append(certs, cert)
	}

	return certs
}
