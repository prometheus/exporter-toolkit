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
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"go.opentelemetry.io/collector/component"
	"go.opentelemetry.io/collector/consumer"
	"go.opentelemetry.io/collector/receiver"
)

// prometheusReceiver implements the receiver.Metrics interface for Prometheus exporters.
type prometheusReceiver struct {
	config      *ReceiverConfig
	consumer    consumer.Metrics
	settings    receiver.Settings
	initializer ExporterInitializer
	scraper     *scraper

	registry *prometheus.Registry
	cancel   context.CancelFunc
	done     chan struct{}
}

// newPrometheusReceiver creates a new Prometheus exporter receiver.
func newPrometheusReceiver(
	config *ReceiverConfig,
	consumer consumer.Metrics,
	settings receiver.Settings,
	initializer ExporterInitializer,
) *prometheusReceiver {
	return &prometheusReceiver{
		config:      config,
		consumer:    consumer,
		settings:    settings,
		initializer: initializer,
		done:        make(chan struct{}),
	}
}

// Start begins the receiver's operation.
// It initializes the exporter and starts the scraping loop.
func (r *prometheusReceiver) Start(ctx context.Context, host component.Host) error {
	r.settings.Logger.Info("Starting Prometheus exporter receiver")

	// Initialize the exporter
	exporterConfig := r.config.GetExporterConfig()
	registry, err := r.initializer.Initialize(ctx, exporterConfig)
	if err != nil {
		return fmt.Errorf("failed to initialize exporter: %w", err)
	}
	r.registry = registry

	// Create the scraper
	r.scraper = newScraper(
		r.registry,
		r.consumer,
		r.settings.Logger,
	)

	// Start the scraping loop
	ctx, cancel := context.WithCancel(context.Background())
	r.cancel = cancel

	go r.scrapeLoop(ctx)

	r.settings.Logger.Info("Prometheus exporter receiver started successfully")
	return nil
}

// Shutdown stops the receiver's operation.
// It stops the scraping loop and shuts down the exporter.
func (r *prometheusReceiver) Shutdown(ctx context.Context) error {
	r.settings.Logger.Info("Shutting down Prometheus exporter receiver")

	// Stop the scraping loop
	if r.cancel != nil {
		r.cancel()
		// Wait for the scrape loop to finish or context to timeout
		select {
		case <-r.done:
			r.settings.Logger.Debug("Scrape loop stopped")
		case <-ctx.Done():
			r.settings.Logger.Warn("Context cancelled before scrape loop finished")
		}
	}

	// Shutdown the exporter
	if r.initializer != nil {
		if err := r.initializer.Shutdown(ctx); err != nil {
			r.settings.Logger.Error("Failed to shutdown exporter")
			return fmt.Errorf("failed to shutdown exporter: %w", err)
		}
	}

	r.settings.Logger.Info("Prometheus exporter receiver shut down successfully")
	return nil
}

// scrapeLoop periodically scrapes metrics from the Prometheus registry
// and sends them to the consumer.
func (r *prometheusReceiver) scrapeLoop(ctx context.Context) {
	defer close(r.done)

	ticker := time.NewTicker(r.config.ScrapeInterval)
	defer ticker.Stop()

	// Perform an immediate scrape on startup
	if err := r.scrapeAndExport(ctx); err != nil {
		r.settings.Logger.Error("Initial scrape failed")
	}

	for {
		select {
		case <-ctx.Done():
			r.settings.Logger.Debug("Scrape loop context cancelled")
			return
		case <-ticker.C:
			if err := r.scrapeAndExport(ctx); err != nil {
				r.settings.Logger.Error("Scrape failed")
				// Continue scraping even if one scrape fails
			}
		}
	}
}

// scrapeAndExport scrapes metrics from the registry and exports them to the consumer.
func (r *prometheusReceiver) scrapeAndExport(ctx context.Context) error {
	metrics, err := r.scraper.Scrape(ctx)
	if err != nil {
		return fmt.Errorf("failed to scrape metrics: %w", err)
	}

	if err := r.consumer.ConsumeMetrics(ctx, metrics); err != nil {
		return fmt.Errorf("failed to consume metrics: %w", err)
	}

	r.settings.Logger.Debug("Metrics scraped and exported")

	return nil
}
