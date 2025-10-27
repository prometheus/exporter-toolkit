# OCB Testing Environment

This directory contains the OpenTelemetry Collector Builder (OCB) testing environment for developing and testing the embedded Prometheus exporter receiver functionality.

## Overview

The OpenTelemetry Collector Builder (OCB) is a tool that generates a custom OpenTelemetry Collector binary with specific components (receivers, processors, exporters, extensions) that you define in a manifest file.

We use OCB to:
1. Build a custom collector that includes our exporter receivers
2. Test the integration of embedded Prometheus exporters
3. Validate that exporters work correctly in the OTel ecosystem

## Directory Structure

```
testing/ocb/
├── README.md                 # This file
├── builder-config.yaml       # OCB manifest (what to include in the build)
├── otel-config.yaml         # Collector runtime config (how to run it)
├── Makefile                 # Build automation
└── dist/                    # Output directory (created by build)
    └── otelcol-exporter-toolkit  # The built collector binary
```

## Prerequisites

### Install OCB (OpenTelemetry Collector Builder)

```bash
# Option 1: Install via go install
go install go.opentelemetry.io/collector/cmd/builder@latest

# Option 2: Download pre-built binary
# Visit: https://github.com/open-telemetry/opentelemetry-collector/releases
# Download the 'ocb' binary for your platform

# Verify installation
ocb version
```

### System Requirements

- Go 1.24 or later
- 2GB+ RAM for building
- Internet connection (for downloading dependencies)

## Quick Start

### 1. Build the Collector

```bash
# From this directory (testing/ocb/)
make build

# Or manually:
ocb --config builder-config.yaml
```

This will:
- Download all specified OTel components
- Generate Go code for the custom collector
- Build the binary to `./dist/otelcol-exporter-toolkit`

**Build time**: First build takes 2-5 minutes (downloads dependencies). Subsequent builds are faster.

### 2. Run the Collector

```bash
# Run with the test config
make run

# Or manually:
./dist/otelcol-exporter-toolkit --config otel-config.yaml
```

### 3. Verify It's Working

Validate the configuration:
```bash
make validate
```

Check what's included:
```bash
make components
```

**Current build includes**:
- ✅ OTLP receiver (minimal receiver to meet requirements)
- ✅ Debug exporter (for testing metrics output)
- ✅ No processors (simplified for our use case)
- ✅ No extensions (simplified for our use case)
- ✅ Ready for custom Prometheus exporter receivers

You can now run the collector:
```bash
make run
# Press Ctrl+C to stop
```

The collector will listen on:
- gRPC: `0.0.0.0:4317`
- HTTP: `0.0.0.0:4318`

**Next steps**: Implement Phase 1 to add the base receiver framework for Prometheus exporters.

## Configuration Files Explained

### builder-config.yaml

The **builder manifest** tells OCB what to include in the collector binary. It has sections for:

- **`dist`**: Build output configuration (binary name, version, etc.)
- **`exporters`**: Where to send telemetry (debug, OTLP, Jaeger, etc.)
- **`processors`**: How to modify/filter telemetry (batch, filter, etc.)
- **`receivers`**: Where telemetry comes from (OTLP, Prometheus, etc.)
- **`extensions`**: Additional features (health check, pprof, etc.)

Each component is specified as a Go module reference:
```yaml
receivers:
  - gomod: go.opentelemetry.io/collector/receiver/otlpreceiver v0.115.0
```

### otel-config.yaml

The **runtime configuration** defines how the collector behaves when running:

- **`extensions`**: Configure enabled extensions (ports, endpoints)
- **`receivers`**: Configure data collection (scrape intervals, endpoints)
- **`processors`**: Configure data processing (batch sizes, filters)
- **`exporters`**: Configure data export destinations
- **`service.pipelines`**: Wire together receivers → processors → exporters

## Development Workflow

### Adding a New Exporter Receiver

1. **Update builder-config.yaml** to include your receiver:
   ```yaml
   receivers:
     - gomod: github.com/prometheus/node_exporter/otlpreceiver v0.1.0
   ```

2. **Rebuild the collector**:
   ```bash
   make build
   ```

3. **Update otel-config.yaml** to configure the receiver:
   ```yaml
   receivers:
     prometheus/node_exporter:
       scrape_interval: 30s
       exporter_config:
         # node_exporter specific config
   ```

4. **Add to pipeline** in the `service.pipelines` section:
   ```yaml
   service:
     pipelines:
       metrics:
         receivers: [otlp, prometheus/node_exporter]
         # ...
   ```

5. **Run and test**:
   ```bash
   make run
   ```

### Iterative Development

When developing a receiver:

```bash
# Clean and rebuild
make clean build

# Or for quick iteration:
make rebuild  # Cleans and rebuilds in one command

# Check logs for errors
make run 2>&1 | tee collector.log
```

## Troubleshooting

### Build Fails with "cannot find module"

**Problem**: OCB can't find your custom receiver module.

**Solutions**:
- Ensure the Go module is published or use `replace` directives
- For local development, add to builder-config.yaml:
  ```yaml
  replaces:
    - github.com/prometheus/exporter-toolkit => ../..
  ```

### Collector Fails to Start

**Problem**: Runtime configuration error.

**Check**:
1. Validate YAML syntax: `yamllint otel-config.yaml`
2. Ensure all receivers in pipelines are defined in receivers section
3. Check logs for specific error messages
4. Verify port conflicts (another service using the ports)

### "Component not found" Error

**Problem**: Component in otel-config.yaml wasn't included in builder-config.yaml.

**Solution**: Add the component to builder-config.yaml and rebuild.

### Performance Issues

**Problem**: Collector uses too much memory/CPU.

**Tune**:
- Adjust `memory_limiter` settings in otel-config.yaml
- Increase `batch` timeout to reduce processing frequency
- Lower telemetry detail level: `telemetry.metrics.level: basic`

## Useful Commands

```bash
# Build only
make build

# Run the collector
make run

# Clean build artifacts
make clean

# Full rebuild
make rebuild

# Show collector version/components
./dist/otelcol-exporter-toolkit --version
./dist/otelcol-exporter-toolkit components

# Validate config (doesn't start collector)
./dist/otelcol-exporter-toolkit validate --config otel-config.yaml

# Run with different config
./dist/otelcol-exporter-toolkit --config my-custom-config.yaml
```

## Debugging

### Check What's Included

```bash
# List all built-in components
./dist/otelcol-exporter-toolkit components

# Should show:
# - receivers: otlp, (your custom receivers)
# - processors: batch, memory_limiter
# - exporters: debug, otlp
# - extensions: health_check, pprof, zpages
```

### Enable Debug Logging

In otel-config.yaml:
```yaml
service:
  telemetry:
    logs:
      level: debug  # Change from 'info' to 'debug'
```

### Use Zpages for Live Debugging

Navigate to http://localhost:55679/debug/tracez (when collector is running) to:
- See active pipeline statistics
- Monitor receiver/exporter health
- View live metrics

## Next Steps

1. ✅ **Phase 0 Complete**: You've set up the OCB environment
2. **Phase 1**: Implement the base receiver framework in `exporter-toolkit/otlpreceiver/`
3. **Phase 2**: Add Prometheus → OTel conversion logic
4. **Phase 3**: Define exporter integration interfaces
5. **Phase 4**: Create a dummy exporter and test in this environment

## Resources

- [OCB Documentation](https://github.com/open-telemetry/opentelemetry-collector/tree/main/cmd/builder)
- [OTel Collector Configuration](https://opentelemetry.io/docs/collector/configuration/)
- [Building Custom Receivers](https://opentelemetry.io/docs/collector/building/receiver/)
- [OTel Collector Architecture](https://opentelemetry.io/docs/collector/architecture/)

---

Happy building! 🚀


