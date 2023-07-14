// Copyright 2023 The Prometheus Authors
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
package toolkit

import (
	"errors"
	stdlog "log"
	"net/http"
	"os"

	"github.com/alecthomas/kingpin/v2"
	"github.com/go-kit/log"
	"github.com/go-kit/log/level"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/prometheus/common/promlog"
	promlogflag "github.com/prometheus/common/promlog/flag"
	"github.com/prometheus/common/version"
	"github.com/prometheus/exporter-toolkit/web"
)

var (
	ErrNoFlagConfig = errors.New("Missing FlagConfig")
	ErrNoHandler    = errors.New("Missing one of MetricsHandler or MetricsHandlerFunc")
	ErrOneHandler   = errors.New("Only one of MetricsHandler or MetricsHandlerFunc allowed")
)

type Config struct {
	Name               string
	Description        string
	DefaultAddress     string
	Logger             log.Logger
	MetricsHandlerFunc *func(http.ResponseWriter, *http.Request)
}

type Toolkit struct {
	Logger      log.Logger
	MaxRequests int

	flagConfig         *web.FlagConfig
	landingConfig      web.LandingConfig
	metricsHandler     http.Handler
	metricsHandlerFunc *func(http.ResponseWriter, *http.Request)
}

func New(c Config) *Toolkit {
	disableExporterMetrics := kingpin.Flag(
		"web.disable-exporter-metrics",
		"Exclude metrics about the exporter itself (promhttp_*, process_*, go_*).",
	).Bool()
	maxRequests := kingpin.Flag(
		"web.max-requests",
		"Maximum number of parallel scrape requests. Use 0 to disable.",
	).Default("40").Int()

	t := Toolkit{
		flagConfig: AddFlags(kingpin.CommandLine, c.DefaultAddress),
		landingConfig: web.LandingConfig{
			Name:        c.Name,
			Description: c.Description,
			Version:     version.Info(),
		},
		metricsHandlerFunc: c.MetricsHandlerFunc,
	}

	promlogConfig := &promlog.Config{}
	promlogflag.AddFlags(kingpin.CommandLine, promlogConfig)

	kingpin.Version(version.Print(c.Name))
	kingpin.HelpFlag.Short('h')
	kingpin.Parse()

	t.Logger = promlog.New(promlogConfig)
	t.MaxRequests = *maxRequests

	handlerOpts := promhttp.HandlerOpts{
		ErrorLog:            stdlog.New(log.NewStdlibAdapter(level.Error(t.Logger)), "", 0),
		MaxRequestsInFlight: t.MaxRequests,
	}
	promHandler := promhttp.InstrumentMetricHandler(
		prometheus.DefaultRegisterer, promhttp.HandlerFor(prometheus.DefaultGatherer, handlerOpts),
	)
	if *disableExporterMetrics {
		prometheus.Unregister(collectors.NewGoCollector())
		prometheus.Unregister(collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}))
		promHandler = promhttp.HandlerFor(prometheus.DefaultGatherer, handlerOpts)
	}

	t.metricsHandler = promHandler

	return &t
}

func (t *Toolkit) SetMetricsHandler(h http.Handler) {
	t.metricsHandler = h
}

func (t *Toolkit) SetMetricsHandlerFunc(h *func(http.ResponseWriter, *http.Request)) {
	t.metricsHandlerFunc = h
}

func (t *Toolkit) Run() error {
	if t.flagConfig == nil {
		return ErrNoFlagConfig
	}
	err := t.flagConfig.CheckFlags()
	if err != nil {
		return err
	}
	if t.metricsHandler == nil && t.metricsHandlerFunc == nil {
		return ErrNoHandler
	}
	if t.metricsHandler != nil && t.metricsHandlerFunc != nil {
		return ErrOneHandler
	}
	if *t.flagConfig.MetricsPath != "" && t.metricsHandler != nil {
		http.Handle(*t.flagConfig.MetricsPath, t.metricsHandler)
	}
	if *t.flagConfig.MetricsPath != "" && t.metricsHandlerFunc != nil {
		http.HandleFunc(*t.flagConfig.MetricsPath, *t.metricsHandlerFunc)
	}
	if *t.flagConfig.MetricsPath != "/" && *t.flagConfig.MetricsPath != "" {
		t.landingConfig.Links = append(t.landingConfig.Links,
			web.LandingLinks{
				Address: *t.flagConfig.MetricsPath,
				Text:    "Metrics",
			},
		)
		landingPage, err := web.NewLandingPage(t.landingConfig)
		if err != nil {
			level.Error(t.Logger).Log("err", err)
			os.Exit(1)
		}
		http.Handle("/", landingPage)
	}

	level.Info(t.Logger).Log("msg", "Starting "+t.landingConfig.Name, "version", version.Info())
	level.Info(t.Logger).Log("msg", "Build context", "build_context", version.BuildContext())

	srv := &http.Server{}
	return web.ListenAndServe(srv, t.flagConfig, t.Logger)
}
