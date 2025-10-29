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
	"context"
	"fmt"

	"github.com/prometheus/client_golang/prometheus"
	"go.opentelemetry.io/collector/component"
	"go.opentelemetry.io/collector/consumer"
	"go.opentelemetry.io/collector/receiver"
)

// ExporterInitializer is the interface that Prometheus exporters must implement
// to be embedded in the OTel Collector.
type ExporterInitializer interface {
	// Initialize sets up the exporter and returns a prometheus.Registry
	// containing all the metrics collectors.
	Initialize(ctx context.Context, exporterConfig Config) (*prometheus.Registry, error)

	// Shutdown cleanly stops the exporter and releases resources.
	Shutdown(ctx context.Context) error
}

// ConfigUnmarshaler is the interface for unmarshaling exporter-specific configuration.
type ConfigUnmarshaler interface {
	// UnmarshalExporterConfig parses the exporter-specific configuration
	// from the raw map into a Config instance.
	UnmarshalExporterConfig(data map[string]interface{}) (Config, error)
}

// FactoryOption is a function that configures a Factory.
type FactoryOption func(*factoryConfig)

// factoryConfig holds the configuration for creating a receiver factory.
type factoryConfig struct {
	typeStr           component.Type
	initializer       ExporterInitializer
	configUnmarshaler ConfigUnmarshaler
	defaultConfig     map[string]interface{}
}

// WithType sets the receiver type identifier.
func WithType(typeStr component.Type) FactoryOption {
	return func(cfg *factoryConfig) {
		cfg.typeStr = typeStr
	}
}

// WithInitializer sets the exporter initializer.
func WithInitializer(initializer ExporterInitializer) FactoryOption {
	return func(cfg *factoryConfig) {
		cfg.initializer = initializer
	}
}

// WithConfigUnmarshaler sets the config unmarshaler.
func WithConfigUnmarshaler(unmarshaler ConfigUnmarshaler) FactoryOption {
	return func(cfg *factoryConfig) {
		cfg.configUnmarshaler = unmarshaler
	}
}

func WithComponentDefaults(defaults map[string]interface{}) FactoryOption {
	return func(cfg *factoryConfig) {
		cfg.defaultConfig = defaults
	}
}

// NewFactory creates a new receiver factory for a Prometheus exporter.
// The factory uses the provided ExporterInitializer and ConfigUnmarshaler
// to manage the exporter lifecycle and configuration.
func NewFactory(opts ...FactoryOption) receiver.Factory {
	cfg := &factoryConfig{}
	for _, opt := range opts {
		opt(cfg)
	}

	if cfg.typeStr.String() == "" {
		panic("receiver type must be specified")
	}
	if cfg.initializer == nil {
		panic("exporter initializer must be specified")
	}
	if cfg.configUnmarshaler == nil {
		panic("config unmarshaler must be specified")
	}

	componentDefaultsFunc := func() component.Config {
		config := createDefaultConfig()
		config.ExporterConfig = cfg.defaultConfig
		return &config
	}

	return receiver.NewFactory(
		cfg.typeStr,
		componentDefaultsFunc,
		receiver.WithMetrics(
			createMetricsReceiver(cfg.initializer, cfg.configUnmarshaler),
			component.StabilityLevelAlpha,
		),
	)
}

// createMetricsReceiver returns a function that creates a metrics receiver instance.
func createMetricsReceiver(
	initializer ExporterInitializer,
	unmarshaler ConfigUnmarshaler,
) receiver.CreateMetricsFunc {
	return func(
		ctx context.Context,
		set receiver.Settings,
		cfg component.Config,
		consumer consumer.Metrics,
	) (receiver.Metrics, error) {
		receiverCfg, ok := cfg.(*ReceiverConfig)
		if !ok {
			return nil, fmt.Errorf("invalid config type: %T", cfg)
		}

		// Unmarshal the exporter-specific config
		if len(receiverCfg.ExporterConfig) > 0 {
			exporterCfg, err := unmarshaler.UnmarshalExporterConfig(receiverCfg.ExporterConfig)
			if err != nil {
				return nil, fmt.Errorf("failed to unmarshal exporter config: %w", err)
			}
			receiverCfg.SetExporterConfig(exporterCfg)
		}

		// Validate the complete configuration
		if err := receiverCfg.Validate(); err != nil {
			return nil, fmt.Errorf("invalid configuration: %w", err)
		}

		// Create the receiver instance
		return newPrometheusReceiver(
			receiverCfg,
			consumer,
			set,
			initializer,
		), nil
	}
}
