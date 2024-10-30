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
	"errors"
	"net/http"

	"github.com/prometheus/exporter-toolkit/web/internal/authentication"
)

const (
	denyReasonCertificateRequired = "certificate required"
	denyReasonBadCertificate      = "bad certificate"
	denyReasonUnknownCA           = "unknown certificate authority"
	denyReasonCertificateExpired  = "expired certificate"
)

// X509Authenticator allows for client certificate verification at HTTP level for X.509 certificates.
// The purpose behind it is to delegate or extend the TLS certificate verification beyond the standard TLS handshake.
type X509Authenticator struct {
	// requireClientCerts specifies whether client certificates are required.
	// This vaguely corresponds to crypto/tls ClientAuthType: https://pkg.go.dev/crypto/tls#ClientAuthType.
	// If true, it is equivalent to RequireAnyClientCert or RequireAndVerifyClientCert.
	requireClientCerts bool

	// verifyOptions returns VerifyOptions used to obtain parameters for Certificate.Verify.
	// Optional: if not provided, the client cert is not verified and hence it does not have to be valid.
	verifyOptions func() x509.VerifyOptions

	// verifyPeerCertificate corresponds to `VerifyPeerCertificate` from crypto/tls Config: https://pkg.go.dev/crypto/tls#Config.
	// It bears the same semantics.
	// Optional: if not provided, it is not invoked on any of the peer certificates.
	verifyPeerCertificate func([][]byte, [][]*x509.Certificate) error
}

// Authenticate performs client cert verification by mimicking the steps the server would normally take during the standard TLS handshake in crypto/tls.
// https://cs.opensource.google/go/go/+/refs/tags/go1.23.2:src/crypto/tls/handshake_server.go;l=874-950
func (x *X509Authenticator) Authenticate(r *http.Request) (bool, string, *authentication.HTTPChallenge, error) {
	if r.TLS == nil {
		return false, "", nil, errors.New("no tls connection state in request")
	}

	if len(r.TLS.PeerCertificates) == 0 && x.requireClientCerts {
		if r.TLS.Version == tls.VersionTLS13 {
			return false, denyReasonCertificateRequired, nil, nil
		}

		return false, denyReasonBadCertificate, nil, nil
	}

	var verifiedChains [][]*x509.Certificate
	if len(r.TLS.PeerCertificates) > 0 && x.verifyOptions != nil {
		opts := x.verifyOptions()
		if opts.Intermediates == nil && len(r.TLS.PeerCertificates) > 1 {
			opts.Intermediates = x509.NewCertPool()
			for _, cert := range r.TLS.PeerCertificates[1:] {
				opts.Intermediates.AddCert(cert)
			}
		}

		chains, err := r.TLS.PeerCertificates[0].Verify(opts)
		if err != nil {
			if errors.As(err, &x509.UnknownAuthorityError{}) {
				return false, denyReasonUnknownCA, nil, nil
			}

			var errCertificateInvalid x509.CertificateInvalidError
			if errors.As(err, &errCertificateInvalid) && errCertificateInvalid.Reason == x509.Expired {
				return false, denyReasonCertificateExpired, nil, nil
			}

			return false, denyReasonBadCertificate, nil, nil
		}

		verifiedChains = chains
	}

	if x.verifyPeerCertificate != nil {
		rawCerts := make([][]byte, 0, len(r.TLS.PeerCertificates))
		for _, c := range r.TLS.PeerCertificates {
			rawCerts = append(rawCerts, c.Raw)
		}

		err := x.verifyPeerCertificate(rawCerts, verifiedChains)
		if err != nil {
			return false, denyReasonBadCertificate, nil, nil
		}
	}

	return true, "", nil, nil
}

func NewX509Authenticator(requireClientCerts bool, verifyOptions func() x509.VerifyOptions, verifyPeerCertificate func([][]byte, [][]*x509.Certificate) error) authentication.Authenticator {
	return &X509Authenticator{
		requireClientCerts:    requireClientCerts,
		verifyOptions:         verifyOptions,
		verifyPeerCertificate: verifyPeerCertificate,
	}
}

var _ authentication.Authenticator = &X509Authenticator{}
