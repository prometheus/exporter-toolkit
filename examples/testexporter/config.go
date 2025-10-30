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

import "fmt"

// Config holds the configuration for the test exporter.
type Config struct {
	// ExporterName is a simple test config field
	ExporterName string `mapstructure:"exporter_name"`
}

// Validate checks if the configuration is valid.
func (c *Config) Validate() error {
	if c.ExporterName == "" {
		return fmt.Errorf("exporter_name cannot be empty")
	}
	return nil
}
