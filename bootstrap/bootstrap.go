// Copyright 2026 The Prometheus Authors
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

// Package bootstrap provides a small bootstrap layer for exporters that want the
// common exporter-toolkit web flags, logging setup, landing page wiring, and
// listener startup behavior.

package bootstrap

import (
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"

	"github.com/alecthomas/kingpin/v2"
	"github.com/prometheus/common/promslog"
	promslogflag "github.com/prometheus/common/promslog/flag"
	"github.com/prometheus/common/version"
	"github.com/prometheus/exporter-toolkit/web"
	"github.com/prometheus/exporter-toolkit/web/kingpinflag"
)

var (
	// ErrNoMetricsHandler is returned when no metrics handler source was configured.
	ErrNoMetricsHandler = errors.New("missing metrics handler")
	// ErrMultipleMetricsSource is returned when both a static handler and a
	// handler factory were configured.
	ErrMultipleMetricsSource = errors.New("only one metrics handler source may be configured")
	// ErrMissingMetricsPathFlag is returned when the metrics path flag was not initialized.
	ErrMissingMetricsPathFlag = errors.New("missing metrics path flag configuration")
)

// MetricsHandlerFactory builds an exporter-specific metrics handler after the
// common toolkit flags have been parsed.
type MetricsHandlerFactory func(*Bootstrap) (http.Handler, error)

// Bootstrap captures parsed startup options that handler factories can use to
// construct exporter-specific HTTP handlers after CLI parsing.
type Bootstrap struct {
	// Logger is the configured logger for the exporter process.
	Logger *slog.Logger
	// FlagConfig contains the parsed exporter-toolkit web flags.
	FlagConfig *web.FlagConfig
	// DisableExporterMetrics reports whether exporter self-metrics should be disabled.
	DisableExporterMetrics bool
	// MaxRequests is the parsed value of --web.max-requests.
	MaxRequests int
}

// Config defines the generic exporter bootstrap inputs.
type Config struct {
	// App is the Kingpin application to register flags on. When nil,
	// kingpin.CommandLine is used.
	App *kingpin.Application
	// Name is the exporter name used for version output and startup logging.
	Name string
	// Description is used as the default landing page description.
	Description string
	// DefaultAddress is the default value for --web.listen-address.
	DefaultAddress string
	// Logger is the logger to use. When nil, toolkit configures promslog flags
	// and builds a logger during Parse.
	Logger *slog.Logger
	// LandingConfig customizes the generated landing page.
	LandingConfig web.LandingConfig
	// MetricsHandler is the static handler to register at the metrics path.
	MetricsHandler http.Handler
	// MetricsHandlerFactory builds the metrics handler after flags are parsed.
	MetricsHandlerFactory MetricsHandlerFactory
}

// Runner manages generic exporter startup around flag parsing, landing page
// setup, and web listener bootstrapping.
type Runner struct {
	app       *kingpin.Application
	logConfig *promslog.Config
	provided  Config

	disableExporterMetrics *bool
	maxRequests            *int

	// Logger is the resolved logger after parsing configuration.
	Logger *slog.Logger
	// FlagConfig contains the parsed exporter-toolkit web flags.
	FlagConfig *web.FlagConfig
	// DisableExporterMetrics is the parsed value of --web.disable-exporter-metrics.
	DisableExporterMetrics bool
	// MaxRequests is the parsed value of --web.max-requests.
	MaxRequests int
	// LandingConfig is the resolved landing page configuration.
	LandingConfig web.LandingConfig
	// MetricsHandler is the configured static metrics handler.
	MetricsHandler http.Handler
	// MetricsHandlerFactory is the configured deferred metrics handler builder.
	MetricsHandlerFactory MetricsHandlerFactory
}

// AddFlags adds the common exporter web flags to a Kingpin application.
func AddFlags(a *kingpin.Application, defaultAddress string) *web.FlagConfig {
	return kingpinflag.AddFlags(a, defaultAddress)
}

// New creates a generic exporter bootstrap instance.
func New(c Config) *Runner {
	app := c.App
	if app == nil {
		app = kingpin.CommandLine
	}

	t := &Runner{
		app:                   app,
		provided:              c,
		Logger:                c.Logger,
		LandingConfig:         c.LandingConfig,
		MetricsHandler:        c.MetricsHandler,
		MetricsHandlerFactory: c.MetricsHandlerFactory,
		FlagConfig:            AddFlags(app, c.DefaultAddress),
		disableExporterMetrics: app.Flag(
			"web.disable-exporter-metrics",
			"Exclude metrics about the exporter itself (promhttp_*, process_*, go_*).",
		).Bool(),
		maxRequests: app.Flag(
			"web.max-requests",
			"Maximum number of parallel scrape requests. Use 0 to disable.",
		).Default("40").Int(),
	}

	if c.Logger == nil {
		t.logConfig = &promslog.Config{}
		promslogflag.AddFlags(app, t.logConfig)
	}

	if c.Name != "" {
		app.Version(version.Print(c.Name))
	}
	app.HelpFlag.Short('h')

	return t
}

// Parse parses the provided arguments and resolves the derived bootstrap state.
func (t *Runner) Parse(args []string) error {
	if _, err := t.app.Parse(args); err != nil {
		return err
	}
	if err := t.FlagConfig.CheckFlags(); err != nil {
		return err
	}
	if t.FlagConfig.MetricsPath == nil || *t.FlagConfig.MetricsPath == "" {
		return ErrMissingMetricsPathFlag
	}
	if *t.maxRequests < 0 {
		return fmt.Errorf("web max requests must be greater than or equal to zero")
	}
	if t.Logger == nil {
		t.Logger = promslog.New(t.logConfig)
	}
	t.DisableExporterMetrics = *t.disableExporterMetrics
	t.MaxRequests = *t.maxRequests
	t.LandingConfig = t.defaultLandingConfig()
	return nil
}

// Run parses os.Args and starts serving the configured exporter endpoints.
func (t *Runner) Run() error {
	return t.RunWithArgs(os.Args[1:])
}

// RunWithArgs parses the provided args and starts the exporter HTTP server.
func (t *Runner) RunWithArgs(args []string) error {
	if err := t.Parse(args); err != nil {
		return err
	}
	handler, err := t.resolveMetricsHandler()
	if err != nil {
		return err
	}
	server, err := t.newServer(handler)
	if err != nil {
		return err
	}
	if t.provided.Name != "" {
		t.Logger.Info("Starting "+t.provided.Name, "version", version.Info())
		t.Logger.Info("Build context", "build_context", version.BuildContext())
	}
	return web.ListenAndServe(server, t.FlagConfig, t.Logger)
}

func (t *Runner) resolveMetricsHandler() (http.Handler, error) {
	sources := 0
	if t.MetricsHandler != nil {
		sources++
	}
	if t.MetricsHandlerFactory != nil {
		sources++
	}
	if sources == 0 {
		return nil, ErrNoMetricsHandler
	}
	if sources > 1 {
		return nil, ErrMultipleMetricsSource
	}
	if t.MetricsHandlerFactory != nil {
		return t.MetricsHandlerFactory(&Bootstrap{
			Logger:                 t.Logger,
			FlagConfig:             t.FlagConfig,
			DisableExporterMetrics: t.DisableExporterMetrics,
			MaxRequests:            t.MaxRequests,
		})
	}
	return t.MetricsHandler, nil
}

func (t *Runner) newServer(metricsHandler http.Handler) (*http.Server, error) {
	mux := http.NewServeMux()
	metricsPath := *t.FlagConfig.MetricsPath
	mux.Handle(metricsPath, metricsHandler)

	if metricsPath != "/" {
		landingConfig := t.LandingConfig
		landingConfig.Links = append(landingConfig.Links, web.LandingLinks{
			Address: metricsPath,
			Text:    "Metrics",
		})
		landingPage, err := web.NewLandingPage(landingConfig)
		if err != nil {
			return nil, err
		}
		mux.Handle("/", landingPage)
	}

	return &http.Server{Handler: mux}, nil
}

func (t *Runner) defaultLandingConfig() web.LandingConfig {
	landingConfig := t.LandingConfig
	if landingConfig.Name == "" {
		landingConfig.Name = t.provided.Name
	}
	if landingConfig.Description == "" {
		landingConfig.Description = t.provided.Description
	}
	if landingConfig.Version == "" {
		landingConfig.Version = version.Info()
	}
	return landingConfig
}
