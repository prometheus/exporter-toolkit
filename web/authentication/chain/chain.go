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
	"strings"

	"github.com/prometheus/exporter-toolkit/web/authentication"
)

type ChainAuthenticator []authentication.Authenticator

func (c ChainAuthenticator) Authenticate(r *http.Request) (bool, string, error) {
	var reasons []string

	for _, a := range c {
		ok, reason, err := a.Authenticate(r)
		if err != nil {
			return false, "", err
		}

		if !ok {
			return false, reason, nil
		}

		if len(reason) > 0 {
			reasons = append(reasons, reason)
		}
	}

	reason := strings.Join(reasons, ";")
	return true, reason, nil
}

func NewChainAuthenticator(authenticators []authentication.Authenticator) authentication.Authenticator {
	return ChainAuthenticator(authenticators)
}

var _ authentication.Authenticator = &ChainAuthenticator{}
