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

package otlpreceiver

import (
	"errors"
	"time"

	"go.opentelemetry.io/collector/component"
)

// Config is the interface that exporter-specific configurations must implement.
// Each Prometheus exporter will provide its own Config implementation.
type Config interface {
	// Validate checks if the configuration is valid.
	Validate() error
}

// ReceiverConfig holds the common configuration for all Prometheus exporter receivers.
type ReceiverConfig struct {
	// ScrapeInterval defines how often to collect metrics from the exporter.
	// Default: 30s
	ScrapeInterval time.Duration `mapstructure:"scrape_interval"`

	// ExporterConfig holds the exporter-specific configuration.
	// This will be unmarshaled by the exporter's ConfigUnmarshaler.
	ExporterConfig map[string]interface{} `mapstructure:"exporter_config"`

	// exporterConfigInstance is the unmarshaled exporter-specific config.
	// This is set by the factory after unmarshaling.
	exporterConfigInstance Config
}

// Validate checks if the ReceiverConfig is valid.
func (cfg *ReceiverConfig) Validate() error {
	if cfg.ScrapeInterval <= 0 {
		return errors.New("scrape_interval must be greater than 0")
	}

	// Validate the exporter-specific config if it exists
	if cfg.exporterConfigInstance != nil {
		if err := cfg.exporterConfigInstance.Validate(); err != nil {
			return err
		}
	}

	return nil
}

// SetExporterConfig sets the unmarshaled exporter-specific configuration.
func (cfg *ReceiverConfig) SetExporterConfig(exporterCfg Config) {
	cfg.exporterConfigInstance = exporterCfg
}

// GetExporterConfig returns the unmarshaled exporter-specific configuration.
func (cfg *ReceiverConfig) GetExporterConfig() Config {
	return cfg.exporterConfigInstance
}

// createDefaultConfig returns a default ReceiverConfig with sensible defaults.
func createDefaultConfig() component.Config {
	return &ReceiverConfig{
		ScrapeInterval: 30 * time.Second,
		ExporterConfig: make(map[string]interface{}),
	}
}
