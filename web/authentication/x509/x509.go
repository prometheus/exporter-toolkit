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
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"net/http"
	"strings"

	"github.com/prometheus/exporter-toolkit/web/authentication"
)

type RequireClientCertsFunc func() bool

type VerifyOptionsFunc func() x509.VerifyOptions

type VerifyPeerCertificateFunc func([][]byte, [][]*x509.Certificate) error

type X509Authenticator struct {
	requireClientCertsFn    RequireClientCertsFunc
	verifyOptionsFn         VerifyOptionsFunc
	verifyPeerCertificateFn VerifyPeerCertificateFunc
}

func columnSeparatedHex(d []byte) string {
	h := strings.ToUpper(hex.EncodeToString(d))
	var sb strings.Builder
	for i, r := range h {
		sb.WriteRune(r)
		if i%2 == 1 && i != len(h)-1 {
			sb.WriteRune(':')
		}
	}
	return sb.String()
}

func certificateIdentifier(c *x509.Certificate) string {
	return fmt.Sprintf(
		"SN=%d, SKID=%s, AKID=%s",
		c.SerialNumber,
		columnSeparatedHex(c.SubjectKeyId),
		columnSeparatedHex(c.AuthorityKeyId),
	)
}

func (x *X509Authenticator) Authenticate(r *http.Request) (bool, string, error) {
	if r.TLS == nil {
		return false, "No TLS connection state in request", nil
	}

	if len(r.TLS.PeerCertificates) == 0 && x.requireClientCertsFn() {
		return false, "A certificate is required to be sent by the client.", nil
	}

	var verifiedChains [][]*x509.Certificate
	if len(r.TLS.PeerCertificates) > 0 && x.verifyOptionsFn != nil {
		opts := x.verifyOptionsFn()
		if opts.Intermediates == nil && len(r.TLS.PeerCertificates) > 1 {
			opts.Intermediates = x509.NewCertPool()
			for _, cert := range r.TLS.PeerCertificates[1:] {
				opts.Intermediates.AddCert(cert)
			}
		}

		chains, err := r.TLS.PeerCertificates[0].Verify(opts)
		if err != nil {
			return false, fmt.Sprintf("verifying certificate %s failed: %v", certificateIdentifier(r.TLS.PeerCertificates[0]), err), nil
		}

		verifiedChains = chains
	}

	if x.verifyPeerCertificateFn != nil {
		rawCerts := make([][]byte, 0, len(r.TLS.PeerCertificates))
		for _, c := range r.TLS.PeerCertificates {
			rawCerts = append(rawCerts, c.Raw)
		}

		err := x.verifyPeerCertificateFn(rawCerts, verifiedChains)
		if err != nil {
			return false, fmt.Sprintf("verifying peer certificate failed: %v", err), nil
		}
	}

	return true, "", nil
}

func NewX509Authenticator(requireClientCertsFn RequireClientCertsFunc, verifyOptionsFn VerifyOptionsFunc, verifyPeerCertificateFn VerifyPeerCertificateFunc) authentication.Authenticator {
	return &X509Authenticator{
		requireClientCertsFn:    requireClientCertsFn,
		verifyOptionsFn:         verifyOptionsFn,
		verifyPeerCertificateFn: verifyPeerCertificateFn,
	}
}

var _ authentication.Authenticator = &X509Authenticator{}

// DefaultVerifyOptions returns VerifyOptions that use the system root certificates, current time,
// and requires certificates to be valid for client auth (x509.ExtKeyUsageClientAuth)
func DefaultVerifyOptions() x509.VerifyOptions {
	return x509.VerifyOptions{
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
}
