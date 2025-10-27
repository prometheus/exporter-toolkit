# Makefile for OCB Testing Environment
# Automates building and running the custom OpenTelemetry Collector

.PHONY: help build run clean rebuild validate components version

# Default target
help:
	@echo "OCB Testing Environment - Available targets:"
	@echo ""
	@echo "  build      - Build the custom collector using OCB"
	@echo "  run        - Run the built collector with test config"
	@echo "  clean      - Remove build artifacts"
	@echo "  rebuild    - Clean and build"
	@echo "  validate   - Validate the collector configuration"
	@echo "  components - List all components in the built collector"
	@echo "  version    - Show collector version information"
	@echo "  check-ocb  - Verify OCB is installed"
	@echo ""

# Check if OCB is installed
check-ocb:
	@which builder > /dev/null || ~/go/bin/builder version > /dev/null 2>&1 || (echo "ERROR: builder not found. Install it with: go install go.opentelemetry.io/collector/cmd/builder@latest" && exit 1)
	@echo "✓ OCB is installed"
	@~/go/bin/builder version || builder version

# Build the collector
build: check-ocb
	@echo "Building custom OpenTelemetry Collector..."
	@echo "This may take a few minutes on first build..."
	~/go/bin/builder --config builder-config.yaml || builder --config builder-config.yaml
	@echo ""
	@echo "✓ Build complete! Binary: ./dist/otelcol-exporter-toolkit"
	@echo ""

# Run the collector
run:
	@if [ ! -f ./dist/otelcol-exporter-toolkit ]; then \
		echo "ERROR: Collector binary not found. Run 'make build' first."; \
		exit 1; \
	fi
	@echo "Starting OpenTelemetry Collector..."
	@echo "Press Ctrl+C to stop"
	@echo ""
	./dist/otelcol-exporter-toolkit --config otel-config.yaml

# Clean build artifacts
clean:
	@echo "Cleaning build artifacts..."
	rm -rf ./dist
	@echo "✓ Clean complete"

# Rebuild from scratch
rebuild: clean build

# Validate configuration
validate:
	@if [ ! -f ./dist/otelcol-exporter-toolkit ]; then \
		echo "ERROR: Collector binary not found. Run 'make build' first."; \
		exit 1; \
	fi
	@echo "Validating configuration..."
	./dist/otelcol-exporter-toolkit validate --config otel-config.yaml
	@echo "✓ Configuration is valid"

# List all components in the built collector
components:
	@if [ ! -f ./dist/otelcol-exporter-toolkit ]; then \
		echo "ERROR: Collector binary not found. Run 'make build' first."; \
		exit 1; \
	fi
	@echo "Components included in this collector:"
	@echo ""
	./dist/otelcol-exporter-toolkit components

# Show version information
version:
	@if [ ! -f ./dist/otelcol-exporter-toolkit ]; then \
		echo "ERROR: Collector binary not found. Run 'make build' first."; \
		exit 1; \
	fi
	./dist/otelcol-exporter-toolkit --version


