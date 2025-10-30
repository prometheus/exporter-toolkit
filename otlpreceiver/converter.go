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
	"fmt"
	"time"

	dto "github.com/prometheus/client_model/go"
	"go.opentelemetry.io/collector/pdata/pcommon"
	"go.opentelemetry.io/collector/pdata/pmetric"
)

// converter handles conversion from Prometheus metric families to OpenTelemetry metrics.
type converter struct {
	// Add any state needed for conversion
}

// newConverter creates a new converter instance.
func newConverter() *converter {
	return &converter{}
}

// convertMetricFamily converts a single Prometheus MetricFamily to OpenTelemetry metrics.
// Currently only supports GAUGE metrics.
func (c *converter) convertMetricFamily(mf *dto.MetricFamily, scopeMetrics pmetric.ScopeMetrics) error {
	if mf == nil || mf.Name == nil {
		return fmt.Errorf("invalid metric family: nil or missing name")
	}

	metricName := *mf.Name
	metricType := mf.GetType()

	// Only handle Gauge metrics for now
	if metricType != dto.MetricType_GAUGE {
		// Skip non-gauge metrics silently
		return nil
	}

	// Create a new metric in the scope
	metric := scopeMetrics.Metrics().AppendEmpty()
	metric.SetName(metricName)

	if mf.Help != nil {
		metric.SetDescription(*mf.Help)
	}

	return c.convertGauge(mf, metric)
}

// convertGauge converts Prometheus gauge metrics to OpenTelemetry gauge metrics.
func (c *converter) convertGauge(mf *dto.MetricFamily, metric pmetric.Metric) error {
	gauge := metric.SetEmptyGauge()

	for _, promMetric := range mf.Metric {
		if promMetric.Gauge == nil {
			continue
		}

		dp := gauge.DataPoints().AppendEmpty()

		// Set timestamp
		if promMetric.TimestampMs != nil {
			dp.SetTimestamp(pcommon.Timestamp(*promMetric.TimestampMs * 1_000_000))
		} else {
			dp.SetTimestamp(pcommon.NewTimestampFromTime(time.Now()))
		}

		// Set value
		if promMetric.Gauge.Value != nil {
			dp.SetDoubleValue(*promMetric.Gauge.Value)
		}

		// Set labels as attributes
		c.setAttributes(promMetric.Label, dp.Attributes())
	}

	return nil
}

// setAttributes converts Prometheus labels to OpenTelemetry attributes.
func (c *converter) setAttributes(labels []*dto.LabelPair, attrs pcommon.Map) {
	for _, label := range labels {
		if label.Name != nil && label.Value != nil {
			attrs.PutStr(*label.Name, *label.Value)
		}
	}
}
