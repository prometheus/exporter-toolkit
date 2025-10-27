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
	"context"
	"fmt"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/exporter-toolkit/otlpreceiver"
)

// Exporter is a minimal test exporter that doesn't collect any real metrics.
type Exporter struct {
	config   *Config
	registry *prometheus.Registry
}

// NewExporter creates a new test exporter instance.
func NewExporter(config *Config) *Exporter {
	return &Exporter{
		config:   config,
		registry: prometheus.NewRegistry(),
	}
}

// Initialize sets up the exporter and returns its registry.
func (e *Exporter) Initialize(ctx context.Context, cfg otlpreceiver.Config) (*prometheus.Registry, error) {
	exporterCfg, ok := cfg.(*Config)
	if !ok {
		return nil, fmt.Errorf("invalid config type: expected *Config, got %T", cfg)
	}

	e.config = exporterCfg

	fmt.Printf("Test exporter initialized with name: %s\n", e.config.ExporterName)

	// Return an empty registry - we'll test with hardcoded metrics
	return e.registry, nil
}

// Shutdown cleanly stops the exporter.
func (e *Exporter) Shutdown(ctx context.Context) error {
	fmt.Printf("Test exporter shutting down: %s\n", e.config.ExporterName)
	return nil
}
