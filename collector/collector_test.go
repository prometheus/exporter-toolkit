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
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/alecthomas/kingpin/v2"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
	dto "github.com/prometheus/client_model/go"
)

// fakeCollector stands in for an exporter's own collector interface. The
// registry never sees this type except as the type parameter, which is the
// property under test.
type fakeCollector struct{ name string }

type fakeConfig struct{ prefix string }

func newTestRegistry(t *testing.T) (*Registry[*fakeCollector, fakeConfig], *kingpin.Application) {
	t.Helper()

	r := NewRegistry[*fakeCollector, fakeConfig]("test")
	r.Register(Descriptor{Name: "cpu", Help: "CPU stats", DefaultEnabled: true},
		func(c fakeConfig) (*fakeCollector, error) { return &fakeCollector{name: c.prefix + "cpu"}, nil })
	r.Register(Descriptor{Name: "disk", Help: "Disk stats", DefaultEnabled: true},
		func(c fakeConfig) (*fakeCollector, error) { return &fakeCollector{name: c.prefix + "disk"}, nil })
	r.Register(Descriptor{Name: "expensive", Help: "Slow stats", DefaultEnabled: false, Requires: []string{"an extension"}},
		func(c fakeConfig) (*fakeCollector, error) { return &fakeCollector{name: c.prefix + "expensive"}, nil })

	app := kingpin.New("test", "").Terminate(nil)
	r.AddFlags(app)
	return r, app
}

func TestDefaultState(t *testing.T) {
	r, app := newTestRegistry(t)
	if _, err := app.Parse(nil); err != nil {
		t.Fatalf("parse: %v", err)
	}

	if got, want := r.Enabled(), []string{"cpu", "disk"}; !slices.Equal(got, want) {
		t.Errorf("Enabled() = %v, want %v", got, want)
	}
	if !r.IsEnabled("cpu") {
		t.Error("cpu should be enabled by default")
	}
	if r.IsEnabled("expensive") {
		t.Error("expensive should be disabled by default")
	}
	if r.IsEnabled("nonexistent") {
		t.Error("unknown collector should report disabled")
	}
}

func TestFlagsOverrideDefaults(t *testing.T) {
	r, app := newTestRegistry(t)
	if _, err := app.Parse([]string{"--no-collector.cpu", "--collector.expensive"}); err != nil {
		t.Fatalf("parse: %v", err)
	}

	if got, want := r.Enabled(), []string{"disk", "expensive"}; !slices.Equal(got, want) {
		t.Errorf("Enabled() = %v, want %v", got, want)
	}
}

// DisableDefaults must leave explicitly-named collectors alone; that is the
// whole point of tracking forced state, and the subtlest thing the exporters
// duplicate today.
func TestDisableDefaultsKeepsExplicitChoices(t *testing.T) {
	r, app := newTestRegistry(t)
	if _, err := app.Parse([]string{"--collector.disk"}); err != nil {
		t.Fatalf("parse: %v", err)
	}
	r.DisableDefaults()

	if got, want := r.Enabled(), []string{"disk"}; !slices.Equal(got, want) {
		t.Errorf("Enabled() = %v, want %v", got, want)
	}
}

func TestSetEnabled(t *testing.T) {
	r, app := newTestRegistry(t)
	if _, err := app.Parse(nil); err != nil {
		t.Fatalf("parse: %v", err)
	}

	if err := r.SetEnabled("expensive", true); err != nil {
		t.Fatalf("SetEnabled: %v", err)
	}
	if !r.IsEnabled("expensive") {
		t.Error("expensive should be enabled after SetEnabled")
	}

	// Marked as forced, so DisableDefaults must not clear it.
	r.DisableDefaults()
	if !r.IsEnabled("expensive") {
		t.Error("SetEnabled should mark the collector as explicitly chosen")
	}

	if err := r.SetEnabled("nope", true); err == nil {
		t.Error("SetEnabled on an unknown collector should error")
	}
}

func TestBuildOnlyEnabled(t *testing.T) {
	r, app := newTestRegistry(t)
	if _, err := app.Parse(nil); err != nil {
		t.Fatalf("parse: %v", err)
	}

	got, err := r.Build(StaticConfig(fakeConfig{prefix: "p-"}))
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("Build() returned %d collectors, want 2", len(got))
	}
	if got["cpu"].name != "p-cpu" {
		t.Errorf("factory config not threaded through: got %q", got["cpu"].name)
	}
	if _, ok := got["expensive"]; ok {
		t.Error("Build() included a disabled collector")
	}
}

func TestBuildCachesInstances(t *testing.T) {
	r, app := newTestRegistry(t)
	if _, err := app.Parse(nil); err != nil {
		t.Fatalf("parse: %v", err)
	}

	first, err := r.Build(StaticConfig(fakeConfig{}))
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	second, err := r.Build(StaticConfig(fakeConfig{}))
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if first["cpu"] != second["cpu"] {
		t.Error("Build() should reuse instantiated collectors")
	}
}

func TestBuildFilters(t *testing.T) {
	r, app := newTestRegistry(t)
	if _, err := app.Parse(nil); err != nil {
		t.Fatalf("parse: %v", err)
	}

	got, err := r.Build(StaticConfig(fakeConfig{}), "cpu")
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if len(got) != 1 || got["cpu"] == nil {
		t.Errorf("Build(filter cpu) = %v, want only cpu", got)
	}

	if _, err := r.Build(StaticConfig(fakeConfig{}), "nope"); err == nil {
		t.Error("filter naming an unknown collector should error")
	}
	if _, err := r.Build(StaticConfig(fakeConfig{}), "expensive"); err == nil {
		t.Error("filter naming a disabled collector should error")
	}
}

func TestBuildFactoryError(t *testing.T) {
	r := NewRegistry[*fakeCollector, fakeConfig]("test")
	r.Register(Descriptor{Name: "broken", DefaultEnabled: true},
		func(fakeConfig) (*fakeCollector, error) { return nil, errors.New("boom") })

	if _, err := r.Build(StaticConfig(fakeConfig{})); err == nil || !strings.Contains(err.Error(), "broken") {
		t.Errorf("Build() error = %v, want one naming the collector", err)
	}
}

func TestReportIncludesDisabled(t *testing.T) {
	r, app := newTestRegistry(t)
	if _, err := app.Parse(nil); err != nil {
		t.Fatalf("parse: %v", err)
	}

	report := r.Report()
	if report.Namespace != "test" {
		t.Errorf("Namespace = %q, want test", report.Namespace)
	}
	if len(report.Collectors) != 3 {
		t.Fatalf("Report listed %d collectors, want all 3", len(report.Collectors))
	}
	// Sorted by name: cpu, disk, expensive.
	if report.Collectors[2].Name != "expensive" || report.Collectors[2].Enabled {
		t.Errorf("expected expensive listed and disabled, got %+v", report.Collectors[2])
	}
	if got := report.Collectors[2].Requires; !slices.Equal(got, []string{"an extension"}) {
		t.Errorf("Requires = %v, want [an extension]", got)
	}
}

func TestWriteJSON(t *testing.T) {
	r, app := newTestRegistry(t)
	if _, err := app.Parse(nil); err != nil {
		t.Fatalf("parse: %v", err)
	}

	var buf strings.Builder
	if err := r.WriteJSON(&buf); err != nil {
		t.Fatalf("WriteJSON: %v", err)
	}
	for _, want := range []string{`"name": "cpu"`, `"enabled": true`, `"default_enabled": false`} {
		if !strings.Contains(buf.String(), want) {
			t.Errorf("JSON missing %s:\n%s", want, buf.String())
		}
	}
}

func TestWriteMarkdown(t *testing.T) {
	r, app := newTestRegistry(t)
	if _, err := app.Parse(nil); err != nil {
		t.Fatalf("parse: %v", err)
	}

	var buf strings.Builder
	if err := r.WriteMarkdown(&buf); err != nil {
		t.Fatalf("WriteMarkdown: %v", err)
	}

	want := "| Collector | Default | Notes |\n" +
		"|---|---|---|\n" +
		"| `cpu` | enabled | CPU stats |\n" +
		"| `disk` | enabled | Disk stats |\n" +
		"| `expensive` | disabled | Slow stats; requires an extension |\n"
	if buf.String() != want {
		t.Errorf("WriteMarkdown() =\n%s\nwant\n%s", buf.String(), want)
	}
}

func TestEnabledMetrics(t *testing.T) {
	r, app := newTestRegistry(t)
	if _, err := app.Parse(nil); err != nil {
		t.Fatalf("parse: %v", err)
	}

	want := `
# HELP test_collector_enabled Whether a collector is enabled in this exporter (1) or not (0).
# TYPE test_collector_enabled gauge
test_collector_enabled{collector="cpu"} 1
test_collector_enabled{collector="disk"} 1
test_collector_enabled{collector="expensive"} 0
`
	if err := testutil.CollectAndCompare(r.EnabledMetrics(), strings.NewReader(want)); err != nil {
		t.Error(err)
	}
}

func TestRegisterDuplicatePanics(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Error("duplicate registration should panic")
		}
	}()

	r := NewRegistry[*fakeCollector, fakeConfig]("test")
	d := Descriptor{Name: "cpu"}
	r.Register(d, func(fakeConfig) (*fakeCollector, error) { return nil, nil })
	r.Register(d, func(fakeConfig) (*fakeCollector, error) { return nil, nil })
}

func TestRegisterAfterAddFlagsPanics(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Error("registration after AddFlags should panic")
		}
	}()

	r, _ := newTestRegistry(t)
	r.Register(Descriptor{Name: "late"}, func(fakeConfig) (*fakeCollector, error) { return nil, nil })
}

func TestScrapeReporter(t *testing.T) {
	s := NewScrapeReporter("test", "test_exporter")

	ch := make(chan prometheus.Metric, 4)
	s.Report(ch, "cpu", 0, nil)
	s.Report(ch, "disk", 0, errors.New("boom"))
	close(ch)

	got := map[string]float64{}
	for m := range ch {
		var pb dto.Metric
		if err := m.Write(&pb); err != nil {
			t.Fatalf("write: %v", err)
		}
		got[m.Desc().String()+pb.GetLabel()[0].GetValue()] = pb.GetGauge().GetValue()
	}

	var success, failure float64 = -1, -1
	for k, v := range got {
		if strings.Contains(k, "collector_success") {
			if strings.HasSuffix(k, "cpu") {
				success = v
			}
			if strings.HasSuffix(k, "disk") {
				failure = v
			}
		}
	}
	if success != 1 {
		t.Errorf("cpu success = %v, want 1", success)
	}
	if failure != 0 {
		t.Errorf("disk success = %v, want 0", failure)
	}
}
