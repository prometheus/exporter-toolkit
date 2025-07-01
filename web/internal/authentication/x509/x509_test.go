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
	"reflect"
	"testing"

	"github.com/prometheus/exporter-toolkit/web/internal/authentication/testhelpers"
)

//go:embed testdata/client_selfsigned.pem
var clientSelfsignedPEM []byte

//go:embed testdata/client2_selfsigned.pem
var client2SelfsignedPEM []byte

func TestX509Authenticator_Authenticate(t *testing.T) {
	t.Parallel()

	tt := []struct {
		Name string

		RequireClientCerts    bool
		VerifyOptions         func() x509.VerifyOptions
		VerifyPeerCertificate func([][]byte, [][]*x509.Certificate) error

		RequestFn func(*testing.T) *http.Request

		ExpectAuthenticated bool
		ExpectedDenyReason  string
		ExpectedError       error
	}{
		{
			Name:                  "No TLS connection state in request",
			RequireClientCerts:    false,
			VerifyOptions:         nil,
			VerifyPeerCertificate: nil,
			RequestFn:             testhelpers.MakeDefaultRequest,
			ExpectAuthenticated:   false,
			ExpectedDenyReason:    "",
			ExpectedError:         errors.New("no tls connection state in request"),
		},
		{
			Name:                  "Certs not required, certs not provided",
			RequireClientCerts:    false,
			VerifyOptions:         nil,
			VerifyPeerCertificate: nil,
			RequestFn: func(t *testing.T) *http.Request {
				t.Helper()

				req := testhelpers.MakeDefaultRequest(t)
				req.TLS = &tls.ConnectionState{}

				return req
			},
			ExpectAuthenticated: true,
			ExpectedDenyReason:  "",
			ExpectedError:       nil,
		},
		{
			Name:                  "Certs required, certs not provided",
			RequireClientCerts:    true,
			VerifyOptions:         nil,
			VerifyPeerCertificate: nil,
			RequestFn: func(t *testing.T) *http.Request {
				t.Helper()

				req := testhelpers.MakeDefaultRequest(t)
				req.TLS = &tls.ConnectionState{}

				return req
			},
			ExpectAuthenticated: false,
			ExpectedDenyReason:  "bad certificate",
			ExpectedError:       nil,
		},
		{
			Name:                  "Certs required, certs not provided, VersionTLS13",
			RequireClientCerts:    true,
			VerifyOptions:         nil,
			VerifyPeerCertificate: nil,
			RequestFn: func(t *testing.T) *http.Request {
				t.Helper()

				req := testhelpers.MakeDefaultRequest(t)
				req.TLS = &tls.ConnectionState{
					Version: tls.VersionTLS13,
				}

				return req
			},
			ExpectAuthenticated: false,
			ExpectedDenyReason:  "certificate required",
			ExpectedError:       nil,
		},
		{
			Name:                  "Certs not required, no verify, selfsigned cert provided",
			RequireClientCerts:    false,
			VerifyOptions:         nil,
			VerifyPeerCertificate: nil,
			RequestFn: func(t *testing.T) *http.Request {
				t.Helper()

				req := testhelpers.MakeDefaultRequest(t)
				req.TLS = &tls.ConnectionState{
					PeerCertificates: getCerts(t, clientSelfsignedPEM),
				}

				return req
			},
			ExpectAuthenticated: true,
			ExpectedDenyReason:  "",
			ExpectedError:       nil,
		},
		{
			Name:                  "Certs required, no verify, selfsigned cert provided",
			RequireClientCerts:    true,
			VerifyOptions:         nil,
			VerifyPeerCertificate: nil,
			RequestFn: func(t *testing.T) *http.Request {
				t.Helper()

				req := testhelpers.MakeDefaultRequest(t)
				req.TLS = &tls.ConnectionState{
					PeerCertificates: getCerts(t, clientSelfsignedPEM),
				}

				return req
			},
			ExpectAuthenticated: true,
			ExpectedDenyReason:  "",
			ExpectedError:       nil,
		},
		{
			Name:               "Certs not required, verify, selfsigned cert provided",
			RequireClientCerts: false,
			VerifyOptions: func() x509.VerifyOptions {
				opts := baseVerifyOptions()
				opts.Roots = getCertPool(t, clientSelfsignedPEM)
				return opts
			},
			VerifyPeerCertificate: nil,
			RequestFn: func(t *testing.T) *http.Request {
				t.Helper()

				req := testhelpers.MakeDefaultRequest(t)
				req.TLS = &tls.ConnectionState{
					PeerCertificates: getCerts(t, clientSelfsignedPEM),
				}

				return req
			},
			ExpectAuthenticated: true,
			ExpectedDenyReason:  "",
			ExpectedError:       nil,
		},
		{
			Name:               "Certs not required, verify, no certs provided",
			RequireClientCerts: false,
			VerifyOptions: func() x509.VerifyOptions {
				opts := baseVerifyOptions()
				opts.Roots = getCertPool(t, clientSelfsignedPEM)
				return opts
			},
			VerifyPeerCertificate: nil,
			RequestFn: func(t *testing.T) *http.Request {
				t.Helper()

				req := testhelpers.MakeDefaultRequest(t)
				req.TLS = &tls.ConnectionState{}

				return req
			},
			ExpectAuthenticated: true,
			ExpectedDenyReason:  "",
			ExpectedError:       nil,
		},
		{
			Name:               "Certs required, verify, selfsigned cert provided",
			RequireClientCerts: true,
			VerifyOptions: func() x509.VerifyOptions {
				opts := baseVerifyOptions()
				opts.Roots = getCertPool(t, clientSelfsignedPEM)
				return opts
			},
			VerifyPeerCertificate: nil,
			RequestFn: func(t *testing.T) *http.Request {
				t.Helper()

				req := testhelpers.MakeDefaultRequest(t)
				req.TLS = &tls.ConnectionState{
					PeerCertificates: getCerts(t, clientSelfsignedPEM),
				}

				return req
			},
			ExpectAuthenticated: true,
			ExpectedDenyReason:  "",
			ExpectedError:       nil,
		},
		{
			Name:               "Certs required, verify, cert signed by an unknown CA provided",
			RequireClientCerts: true,
			VerifyOptions: func() x509.VerifyOptions {
				opts := baseVerifyOptions()
				opts.Roots = getCertPool(t, clientSelfsignedPEM)
				return opts
			},
			VerifyPeerCertificate: nil,
			RequestFn: func(t *testing.T) *http.Request {
				t.Helper()

				req := testhelpers.MakeDefaultRequest(t)
				req.TLS = &tls.ConnectionState{
					PeerCertificates: getCerts(t, client2SelfsignedPEM),
				}

				return req
			},
			ExpectAuthenticated: false,
			ExpectedDenyReason:  "unknown certificate authority",
			ExpectedError:       nil,
		},
		{
			Name:               "Certs required, verify, selfsigned cert provided, verify peer certificate func returns an error",
			RequireClientCerts: true,
			VerifyOptions: func() x509.VerifyOptions {
				opts := baseVerifyOptions()
				opts.Roots = getCertPool(t, clientSelfsignedPEM)
				return opts
			},
			VerifyPeerCertificate: func(_ [][]byte, _ [][]*x509.Certificate) error {
				return errors.New("invalid peer certificate")
			},
			RequestFn: func(t *testing.T) *http.Request {
				t.Helper()

				req := testhelpers.MakeDefaultRequest(t)
				req.TLS = &tls.ConnectionState{
					PeerCertificates: getCerts(t, clientSelfsignedPEM),
				}

				return req
			},
			ExpectAuthenticated: false,
			ExpectedDenyReason:  "bad certificate",
			ExpectedError:       nil,
		},
		{
			Name:               "RequireAndVerifyClientCert, selfsigned certs, verify peer certificate func does not return an error",
			RequireClientCerts: true,
			VerifyOptions: func() x509.VerifyOptions {
				opts := baseVerifyOptions()
				opts.Roots = getCertPool(t, clientSelfsignedPEM)
				return opts
			},
			VerifyPeerCertificate: func(_ [][]byte, _ [][]*x509.Certificate) error {
				return nil
			},
			RequestFn: func(t *testing.T) *http.Request {
				t.Helper()

				req := testhelpers.MakeDefaultRequest(t)
				req.TLS = &tls.ConnectionState{
					PeerCertificates: getCerts(t, clientSelfsignedPEM),
				}

				return req
			},
			ExpectAuthenticated: true,
			ExpectedDenyReason:  "",
			ExpectedError:       nil,
		},
	}

	for _, tc := range tt {
		t.Run(tc.Name, func(t *testing.T) {
			t.Parallel()

			req := tc.RequestFn(t)

			a := NewX509Authenticator(tc.RequireClientCerts, tc.VerifyOptions, tc.VerifyPeerCertificate)
			authenticated, denyReason, httpChallenge, err := a.Authenticate(req)

			if !reflect.DeepEqual(err, tc.ExpectedError) {
				t.Fatalf("Expected error %v, got %v", tc.ExpectedError, err)
			}

			if httpChallenge != nil {
				t.Errorf("Expected http challenge to be nil, got %v", httpChallenge)
			}

			if tc.ExpectedDenyReason != denyReason {
				t.Errorf("Expected deny reason %q, got %q", tc.ExpectedDenyReason, denyReason)
			}

			if tc.ExpectAuthenticated != authenticated {
				t.Errorf("Expected authenticated %t, got %t", tc.ExpectAuthenticated, authenticated)
			}
		})
	}
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

// baseVerifyOptions require certificates to be valid for client auth (x509.ExtKeyUsageClientAuth).
func baseVerifyOptions() x509.VerifyOptions {
	return x509.VerifyOptions{
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
}
