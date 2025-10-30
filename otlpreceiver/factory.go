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

	"github.com/mitchellh/mapstructure"
	"github.com/prometheus/client_golang/prometheus"
	"go.opentelemetry.io/collector/component"
	"go.opentelemetry.io/collector/consumer"
	"go.opentelemetry.io/collector/receiver"
)

// ExporterLifecycleManager is the interface that Prometheus exporters must implement
// to be embedded in the OTel Collector.
type ExporterLifecycleManager interface {
	// Start sets up the exporter and returns a prometheus.Registry
	// containing all the metrics collectors.
	Start(ctx context.Context, exporterConfig Config) (*prometheus.Registry, error)

	// Shutdown is used to release resources when the receiver is shutting down.
	Shutdown(ctx context.Context) error
}

// ConfigUnmarshaler is the interface used to unmarshal the exporter-specific
// configuration using mapstructure and struct tags.
type ConfigUnmarshaler interface {
	// GetConfigStruct returns a pointer to the config struct that mapstructure
	// will populate. The struct should have appropriate mapstructure tags.
	GetConfigStruct() Config
}

// FactoryOption is a function that configures a Factory.
type FactoryOption func(*factoryConfig)

type factoryConfig struct {
	typeStr           component.Type
	lifecycleManager  ExporterLifecycleManager
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
func WithLifecycleManager(lifecycleManager ExporterLifecycleManager) FactoryOption {
	return func(cfg *factoryConfig) {
		cfg.lifecycleManager = lifecycleManager
	}
}

// WithConfigUnmarshaler sets the config unmarshaler.
func WithConfigUnmarshaler(unmarshaler ConfigUnmarshaler) FactoryOption {
	return func(cfg *factoryConfig) {
		cfg.configUnmarshaler = unmarshaler
	}
}

// WithComponentDefaults sets the default configuration for the component.
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
	if cfg.lifecycleManager == nil {
		panic("exporter initializer must be specified")
	}
	if cfg.configUnmarshaler == nil {
		panic("config unmarshaler must be specified")
	}

	componentDefaultsFunc := func() component.Config {
		receiverConfig := createDefaultConfig()
		receiverConfig.ExporterConfig = cfg.defaultConfig
		return &receiverConfig
	}

	return receiver.NewFactory(
		cfg.typeStr,
		componentDefaultsFunc,
		receiver.WithMetrics(
			createMetricsReceiver(cfg.lifecycleManager, cfg.configUnmarshaler),
			component.StabilityLevelAlpha,
		),
	)
}

func createMetricsReceiver(
	lifecycleManager ExporterLifecycleManager,
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

		if len(receiverCfg.ExporterConfig) > 0 {
			exporterCfg := unmarshaler.GetConfigStruct()
			decoder, err := mapstructure.NewDecoder(&mapstructure.DecoderConfig{
				Result:           exporterCfg,
				ErrorUnused:      true,  // Reject unknown fields
				WeaklyTypedInput: false, // Strict type checking
				TagName:          "mapstructure",
			})
			if err != nil {
				return nil, fmt.Errorf("failed to create decoder: %w", err)
			}

			if err = decoder.Decode(receiverCfg.ExporterConfig); err != nil {
				return nil, fmt.Errorf("configuration validation failed: %w", err)
			}

			receiverCfg.SetExporterConfig(exporterCfg)
		}

		if err := receiverCfg.Validate(); err != nil {
			return nil, fmt.Errorf("invalid configuration: %w", err)
		}

		return newPrometheusReceiver(
			receiverCfg,
			consumer,
			set,
			lifecycleManager,
		), nil
	}
}
