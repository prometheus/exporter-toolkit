// Copyright 2024 The Prometheus Authors
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

//go:build nobcrypt
// +build nobcrypt

package basic_auth

import (
	"fmt"
	"log/slog"

	config_util "github.com/prometheus/common/config"
)

func Validate(users map[string]config_util.Secret) error {
	if len(users) > 0 {
		slog.Info("basic auth via bcrypt hashes not implemented")
	}
	return nil
}

func CompareAndHash(hashedPassword, pass []byte) error {
	return fmt.Errorf("basic auth via bcrypt hashes not implemented")
}
