// Copyright 2019 The Prometheus Authors
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

//go:build go1.14 && !nobcrypt
// +build go1.14,!nobcrypt

package web

import "testing"

func TestYAMLFilesUsers(t *testing.T) {
	testTables := []*TestInputs{
		{
			Name:           `invalid config yml (invalid user list)`,
			YAMLConfigPath: "testdata/web_config_auth_user_list_invalid.bad.yml",
			ExpectedError:  ErrorMap["Bad password"],
		},
	}
	for _, testInputs := range testTables {
		t.Run("run/"+testInputs.Name, testInputs.Test)
		t.Run("validate/"+testInputs.Name, testInputs.TestValidate)
	}
}

func TestUsers(t *testing.T) {
	testTables := []*TestInputs{
		{
			Name:           `without basic auth`,
			YAMLConfigPath: "testdata/web_config_users_noTLS.good.yml",
			ExpectedError:  ErrorMap["Unauthorized"],
		},
		{
			Name:           `with correct basic auth`,
			YAMLConfigPath: "testdata/web_config_users_noTLS.good.yml",
			Username:       "dave",
			Password:       "dave123",
			ExpectedError:  nil,
		},
		{
			Name:           `without basic auth and TLS`,
			YAMLConfigPath: "testdata/web_config_users.good.yml",
			UseTLSClient:   true,
			ExpectedError:  ErrorMap["Unauthorized"],
		},
		{
			Name:           `with correct basic auth and TLS`,
			YAMLConfigPath: "testdata/web_config_users.good.yml",
			UseTLSClient:   true,
			Username:       "dave",
			Password:       "dave123",
			ExpectedError:  nil,
		},
		{
			Name:           `with another correct basic auth and TLS`,
			YAMLConfigPath: "testdata/web_config_users.good.yml",
			UseTLSClient:   true,
			Username:       "carol",
			Password:       "carol123",
			ExpectedError:  nil,
		},
		{
			Name:           `with bad password and TLS`,
			YAMLConfigPath: "testdata/web_config_users.good.yml",
			UseTLSClient:   true,
			Username:       "dave",
			Password:       "bad",
			ExpectedError:  ErrorMap["Unauthorized"],
		},
		{
			Name:           `with bad username and TLS`,
			YAMLConfigPath: "testdata/web_config_users.good.yml",
			UseTLSClient:   true,
			Username:       "nonexistent",
			Password:       "nonexistent",
			ExpectedError:  ErrorMap["Unauthorized"],
		},
	}
	for _, testInputs := range testTables {
		t.Run(testInputs.Name, testInputs.Test)
	}
}
