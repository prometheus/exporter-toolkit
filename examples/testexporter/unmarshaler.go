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

package testexporter

import (
	"fmt"

	"github.com/prometheus/exporter-toolkit/otlpreceiver"
)

// ConfigUnmarshaler handles unmarshaling of test exporter configuration.
type ConfigUnmarshaler struct{}

// UnmarshalExporterConfig parses the exporter-specific configuration.
func (u *ConfigUnmarshaler) UnmarshalExporterConfig(data map[string]interface{}) (otlpreceiver.Config, error) {
	cfg := &Config{}

	// Simple manual unmarshaling for our minimal config
	if name, ok := data["exporter_name"].(string); ok {
		cfg.ExporterName = name
	}

	if cfg.ExporterName == "" {
		return nil, fmt.Errorf("exporter_name is required")
	}

	return cfg, nil
}
