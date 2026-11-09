// Copyright The Prometheus Authors
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
	"sync/atomic"
	"testing"
	"time"

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

func mustRegister(t *testing.T, r *Registry[*fakeCollector, fakeConfig], d Descriptor) {
	t.Helper()
	err := r.Register(d, func(c fakeConfig) (*fakeCollector, error) { return &fakeCollector{name: c.prefix + d.Name}, nil })
	if err != nil {
		t.Fatalf("Register(%s): %v", d.Name, err)
	}
}

func newTestRegistry(t *testing.T) (*Registry[*fakeCollector, fakeConfig], *kingpin.Application) {
	t.Helper()

	r := NewRegistry[*fakeCollector, fakeConfig]("test")
	mustRegister(t, r, Descriptor{Name: "cpu", Help: "CPU stats", DefaultEnabled: true})
	mustRegister(t, r, Descriptor{Name: "disk", Help: "Disk stats", DefaultEnabled: true})
	mustRegister(t, r, Descriptor{Name: "expensive", Help: "Slow stats", DefaultEnabled: false, Requires: []string{"an extension"}})

	app := kingpin.New("test", "").Terminate(nil)
	if err := r.AddFlags(app); err != nil {
		t.Fatalf("AddFlags: %v", err)
	}
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

func TestDisableDefaultsKeepsExplicitChoicesInAnyOrder(t *testing.T) {
	for _, args := range [][]string{
		{"--collector.disable-defaults", "--collector.disk"},
		{"--collector.disk", "--collector.disable-defaults"},
	} {
		r, app := newTestRegistry(t)
		if _, err := app.Parse(args); err != nil {
			t.Fatalf("parse %v: %v", args, err)
		}
		if got, want := r.Enabled(), []string{"disk"}; !slices.Equal(got, want) {
			t.Errorf("args %v: Enabled() = %v, want %v", args, got, want)
		}
	}
}

func TestSetEnabledSurvivesParse(t *testing.T) {
	r, app := newTestRegistry(t)
	if err := r.SetEnabled("expensive", true); err != nil {
		t.Fatalf("SetEnabled: %v", err)
	}
	if _, err := app.Parse([]string{"--collector.disable-defaults"}); err != nil {
		t.Fatalf("parse: %v", err)
	}
	if got, want := r.Enabled(), []string{"expensive"}; !slices.Equal(got, want) {
		t.Errorf("Enabled() = %v, want %v", got, want)
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

func TestBuildRepeatedFilterBuildsOnce(t *testing.T) {
	r := NewRegistry[*fakeCollector, fakeConfig]("test")
	calls := 0
	if err := r.Register(Descriptor{Name: "cpu", DefaultEnabled: true},
		func(fakeConfig) (*fakeCollector, error) { calls++; return &fakeCollector{}, nil }); err != nil {
		t.Fatalf("Register: %v", err)
	}

	if _, err := r.Build(StaticConfig(fakeConfig{}), "cpu", "cpu"); err != nil {
		t.Fatalf("Build: %v", err)
	}
	if calls != 1 {
		t.Errorf("factory ran %d times for collect[]=cpu&collect[]=cpu, want 1", calls)
	}
}

func TestConcurrentFirstBuildRunsFactoryOnce(t *testing.T) {
	r := NewRegistry[*fakeCollector, fakeConfig]("test")
	var calls atomic.Int32
	release := make(chan struct{})
	if err := r.Register(Descriptor{Name: "cpu", DefaultEnabled: true},
		func(fakeConfig) (*fakeCollector, error) {
			calls.Add(1)
			<-release
			return &fakeCollector{}, nil
		}); err != nil {
		t.Fatalf("Register: %v", err)
	}

	results := make(chan *fakeCollector, 2)
	for range 2 {
		go func() {
			built, err := r.Build(StaticConfig(fakeConfig{}))
			if err != nil {
				t.Errorf("Build: %v", err)
			}
			results <- built["cpu"]
		}()
	}
	// Give the second Build time to reach the factory if nothing stops it.
	time.Sleep(50 * time.Millisecond)
	close(release)

	first, second := <-results, <-results
	if calls.Load() != 1 {
		t.Errorf("factory ran %d times for two concurrent first builds, want 1", calls.Load())
	}
	if first != second {
		t.Error("concurrent builds returned different instances")
	}
}

func TestBuildRetriesAfterFactoryError(t *testing.T) {
	r := NewRegistry[*fakeCollector, fakeConfig]("test")
	fail := true
	if err := r.Register(Descriptor{Name: "cpu", DefaultEnabled: true},
		func(fakeConfig) (*fakeCollector, error) {
			if fail {
				return nil, errors.New("boom")
			}
			return &fakeCollector{}, nil
		}); err != nil {
		t.Fatalf("Register: %v", err)
	}

	if _, err := r.Build(StaticConfig(fakeConfig{})); err == nil {
		t.Fatal("first Build should fail")
	}
	fail = false
	if built, err := r.Build(StaticConfig(fakeConfig{})); err != nil || built["cpu"] == nil {
		t.Errorf("Build after a factory error = %v, %v, want a built cpu collector", built, err)
	}
}

func TestBuildFactoryError(t *testing.T) {
	r := NewRegistry[*fakeCollector, fakeConfig]("test")
	if err := r.Register(Descriptor{Name: "broken", DefaultEnabled: true},
		func(fakeConfig) (*fakeCollector, error) { return nil, errors.New("boom") }); err != nil {
		t.Fatalf("Register: %v", err)
	}

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

func TestDescriptorsDoNotShareRequires(t *testing.T) {
	requires := []string{"an extension"}
	r := NewRegistry[*fakeCollector, fakeConfig]("test")
	mustRegister(t, r, Descriptor{Name: "expensive", Requires: requires})

	requires[0] = "changed by caller"
	r.Descriptors()[0].Requires[0] = "changed via Descriptors"
	r.Report().Collectors[0].Requires[0] = "changed via Report"

	if got := r.Report().Collectors[0].Requires; !slices.Equal(got, []string{"an extension"}) {
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

func TestWriteMarkdownKeepsRowOnOneLine(t *testing.T) {
	r := NewRegistry[*fakeCollector, fakeConfig]("test")
	mustRegister(t, r, Descriptor{Name: "cpu", Help: "Scrapes X.\nNeeds a|b."})

	var buf strings.Builder
	if err := r.WriteMarkdown(&buf); err != nil {
		t.Fatalf("WriteMarkdown: %v", err)
	}
	if want := "| `cpu` | disabled | Scrapes X. Needs a\\|b. |\n"; !strings.HasSuffix(buf.String(), want) {
		t.Errorf("WriteMarkdown() =\n%s\nwant last row %q", buf.String(), want)
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

func TestBuildAllowsCallbacksIntoRegistry(t *testing.T) {
	r, app := newTestRegistry(t)
	if _, err := app.Parse(nil); err != nil {
		t.Fatalf("parse: %v", err)
	}

	done := make(chan error, 1)
	go func() {
		_, err := r.Build(func(name string) fakeConfig {
			r.IsEnabled(name)
			return fakeConfig{}
		})
		done <- err
	}()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Build: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Build deadlocked when cfgFor called back into the registry")
	}
}

func TestRegisterErrors(t *testing.T) {
	r, _ := newTestRegistry(t)
	factory := func(fakeConfig) (*fakeCollector, error) { return nil, nil }

	for name, err := range map[string]error{
		"empty name":     r.Register(Descriptor{}, factory),
		"duplicate":      r.Register(Descriptor{Name: "cpu"}, factory),
		"after AddFlags": r.Register(Descriptor{Name: "late"}, factory),
		"nil factory":    NewRegistry[*fakeCollector, fakeConfig]("test").Register(Descriptor{Name: "x"}, nil),
		"AddFlags twice": r.AddFlags(kingpin.New("again", "")),
	} {
		if err == nil {
			t.Errorf("%s: want an error", name)
		}
	}
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
