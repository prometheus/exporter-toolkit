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

//go:build go1.18 && !go1.21
// +build go1.18,!go1.21

package web

import (
	"testing"
)

func TestServerBehaviour118(t *testing.T) {
	testTables := []*TestInputs{
		{
			Name:           `valid tls config yml and tls client with RequireAnyClientCert`,
			YAMLConfigPath: "testdata/tls_config_noAuth.requireanyclientcert.good.yml",
			UseTLSClient:   true,
			ExpectedError:  ErrorMap["Bad certificate"],
		},
		{
			Name:           `valid tls config yml and tls client with RequireAndVerifyClientCert`,
			YAMLConfigPath: "testdata/tls_config_noAuth.requireandverifyclientcert.good.yml",
			UseTLSClient:   true,
			ExpectedError:  ErrorMap["Bad certificate"],
		},
		{
			Name:              `valid tls config yml and tls client with RequireAndVerifyClientCert (present wrong certificate)`,
			YAMLConfigPath:    "testdata/tls_config_noAuth.requireandverifyclientcert.good.yml",
			UseTLSClient:      true,
			ClientCertificate: "client2_selfsigned",
			ExpectedError:     ErrorMap["Bad certificate"],
		},
	}
	for _, testInputs := range testTables {
		t.Run(testInputs.Name, testInputs.Test)
	}
}
