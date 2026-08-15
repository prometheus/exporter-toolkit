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

package collector

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

// State is a Descriptor plus whether the collector is currently enabled. It is
// the serialized unit of the introspection API: one row of "what does this
// exporter have, and is it on".
type State struct {
	Descriptor
	Enabled bool `json:"enabled"`
}

// Report is the full machine-readable answer to "what collectors does this
// exporter have?". It is the same shape for every exporter, which is the point:
// tooling that can read one exporter's report can read all of them.
type Report struct {
	Namespace  string  `json:"namespace"`
	Collectors []State `json:"collectors"`
}

// Report returns the current state of every registered collector, sorted by
// name.
func (r *Registry[C, Cfg]) Report() Report {
	descs := r.Descriptors()
	enabled := make(map[string]bool)
	for _, name := range r.Enabled() {
		enabled[name] = true
	}

	out := Report{Namespace: r.namespace, Collectors: make([]State, 0, len(descs))}
	for _, d := range descs {
		out.Collectors = append(out.Collectors, State{Descriptor: d, Enabled: enabled[d.Name]})
	}
	return out
}

// WriteJSON writes the Report as indented JSON. It backs the hidden
// `--collector.list` style flag: machine-readable on purpose, so that each
// exporter's docs pipeline can render it however it likes instead of being
// stuck with one hard-coded table layout.
func (r *Registry[C, Cfg]) WriteJSON(w io.Writer) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(r.Report())
}

// WriteMarkdown writes the collector list as a Markdown table, for exporters
// that want the default rendering rather than their own. The output is stable
// across runs so it can be diffed in CI or embedded with a tool like mdox.
//
// Note this reflects default state, not the state of the running process: docs
// should describe what an operator gets out of the box.
func (r *Registry[C, Cfg]) WriteMarkdown(w io.Writer) error {
	var b strings.Builder

	b.WriteString("| Collector | Default | Notes |\n|---|---|---|\n")
	for _, d := range r.Descriptors() {
		state := "disabled"
		if d.DefaultEnabled {
			state = "enabled"
		}

		notes := d.Help
		if len(d.Requires) > 0 {
			req := "requires " + strings.Join(d.Requires, ", ")
			if notes == "" {
				notes = req
			} else {
				notes += "; " + req
			}
		}

		fmt.Fprintf(&b, "| `%s` | %s | %s |\n", d.Name, state, notes)
	}

	_, err := io.WriteString(w, b.String())
	return err
}

// EnabledMetrics returns a prometheus.Collector exposing
// `<namespace>_collector_enabled{collector="<name>"}` as 1 or 0 for every
// registered collector.
//
// This is the runtime half of the introspection story. A flag only answers
// "what is enabled" for someone who can reach the process; a metric answers it
// for a whole fleet, and makes it possible to alert on an exporter that shipped
// with a collector unintentionally off.
func (r *Registry[C, Cfg]) EnabledMetrics() prometheus.Collector {
	return &enabledMetrics{
		desc: prometheus.NewDesc(
			prometheus.BuildFQName(r.namespace, "", "collector_enabled"),
			"Whether a collector is enabled in this exporter (1) or not (0).",
			[]string{"collector"},
			nil,
		),
		report: r.Report,
	}
}

type enabledMetrics struct {
	desc   *prometheus.Desc
	report func() Report
}

func (e *enabledMetrics) Describe(ch chan<- *prometheus.Desc) {
	ch <- e.desc
}

func (e *enabledMetrics) Collect(ch chan<- prometheus.Metric) {
	for _, c := range e.report().Collectors {
		value := 0.0
		if c.Enabled {
			value = 1.0
		}
		ch <- prometheus.MustNewConstMetric(e.desc, prometheus.GaugeValue, value, c.Name)
	}
}

// ScrapeReporter emits the per-collector scrape duration and success metrics
// that exporters currently redefine identically. Exporters keep their own
// Collect loop — only the bookkeeping is shared.
type ScrapeReporter struct {
	durationDesc *prometheus.Desc
	successDesc  *prometheus.Desc
}

// NewScrapeReporter builds a reporter emitting
// `<namespace>_scrape_collector_duration_seconds` and
// `<namespace>_scrape_collector_success`. exporter is used in the help text,
// e.g. "node_exporter".
func NewScrapeReporter(namespace, exporter string) *ScrapeReporter {
	return &ScrapeReporter{
		durationDesc: prometheus.NewDesc(
			prometheus.BuildFQName(namespace, "scrape", "collector_duration_seconds"),
			fmt.Sprintf("%s: Duration of a collector scrape.", exporter),
			[]string{"collector"},
			nil,
		),
		successDesc: prometheus.NewDesc(
			prometheus.BuildFQName(namespace, "scrape", "collector_success"),
			fmt.Sprintf("%s: Whether a collector succeeded.", exporter),
			[]string{"collector"},
			nil,
		),
	}
}

// Describe sends both descriptors, for use from an exporter's Describe method.
func (s *ScrapeReporter) Describe(ch chan<- *prometheus.Desc) {
	ch <- s.durationDesc
	ch <- s.successDesc
}

// Report emits the duration and success metrics for one collector run.
// success is derived from err being nil.
func (s *ScrapeReporter) Report(ch chan<- prometheus.Metric, name string, duration time.Duration, err error) {
	success := 1.0
	if err != nil {
		success = 0.0
	}
	ch <- prometheus.MustNewConstMetric(s.durationDesc, prometheus.GaugeValue, duration.Seconds(), name)
	ch <- prometheus.MustNewConstMetric(s.successDesc, prometheus.GaugeValue, success, name)
}
