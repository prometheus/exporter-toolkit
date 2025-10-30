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
	dto "github.com/prometheus/client_model/go"
	"go.opentelemetry.io/collector/consumer"
	"go.opentelemetry.io/collector/pdata/pmetric"
	"go.uber.org/zap"
)

// scraper handles scraping metrics from a Prometheus registry and converting
// them to OpenTelemetry format.
type scraper struct {
	registry  *prometheus.Registry
	consumer  consumer.Metrics
	logger    *zap.Logger
	converter *converter
}

// newScraper creates a new scraper instance.
func newScraper(
	registry *prometheus.Registry,
	consumer consumer.Metrics,
	logger *zap.Logger,
) *scraper {
	return &scraper{
		registry:  registry,
		consumer:  consumer,
		logger:    logger,
		converter: newConverter(),
	}
}

// Scrape collects metrics from the Prometheus registry and converts them
// to OpenTelemetry pmetric.Metrics format.
func (s *scraper) Scrape(ctx context.Context) (pmetric.Metrics, error) {
	// Gather metrics from the Prometheus registry
	metricFamilies, err := s.registry.Gather()
	if err != nil {
		return pmetric.Metrics{}, fmt.Errorf("failed to gather metrics: %w", err)
	}

	s.logger.Debug("Gathered metrics from registry")

	// Convert Prometheus metrics to OpenTelemetry format
	metrics := pmetric.NewMetrics()

	// TODO: Implement conversion in Phase 2
	// For now, create a placeholder that will be replaced with actual conversion logic
	if err := s.convertMetrics(metricFamilies, metrics); err != nil {
		return pmetric.Metrics{}, fmt.Errorf("failed to convert metrics: %w", err)
	}

	return metrics, nil
}

// convertMetrics converts Prometheus metric families to OpenTelemetry metrics.
func (s *scraper) convertMetrics(metricFamilies []*dto.MetricFamily, dest pmetric.Metrics) error {
	if len(metricFamilies) == 0 {
		s.logger.Debug("No metrics to convert")
		return nil
	}

	// Create a resource metrics entry
	rm := dest.ResourceMetrics().AppendEmpty()

	// Add resource attributes
	rm.Resource().Attributes().PutStr("service.name", "prometheus-exporter")
	rm.Resource().Attributes().PutStr("exporter.type", "prometheus")

	// Create a scope metrics entry
	sm := rm.ScopeMetrics().AppendEmpty()
	sm.Scope().SetName("prometheus_exporter")
	sm.Scope().SetVersion("1.0.0")

	// Convert each metric family
	for _, mf := range metricFamilies {
		if mf == nil {
			continue
		}

		err := s.converter.convertMetricFamily(mf, sm)
		if err != nil {
			s.logger.Debug("Failed to convert metric family")
			continue
		}
	}

	s.logger.Debug("Converted Prometheus metrics to OpenTelemetry format")

	return nil
}
