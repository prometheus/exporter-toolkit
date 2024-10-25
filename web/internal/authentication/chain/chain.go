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

package chain

import (
	"net/http"

	"github.com/prometheus/exporter-toolkit/web/internal/authentication"
)

// ChainAuthenticator allows for composing multiple authenticators to be used in sequence.
type ChainAuthenticator []authentication.Authenticator

// Authenticate sequentially authenticates the requests against the chained authenticators.
// A request passes authentication when all composed authenticators accept it.
// If either denies in the process, it returns early and the following authenticators are not invoked.
func (c ChainAuthenticator) Authenticate(r *http.Request) (bool, string, *authentication.HTTPChallenge, error) {
	for _, a := range c {
		ok, denyReason, httpChallenge, err := a.Authenticate(r)
		if err != nil {
			return false, "", nil, err
		}

		if !ok {
			return false, denyReason, httpChallenge, nil
		}
	}

	return true, "", nil, nil
}

func NewChainAuthenticator(authenticators []authentication.Authenticator) authentication.Authenticator {
	return ChainAuthenticator(authenticators)
}

var _ authentication.Authenticator = &ChainAuthenticator{}
