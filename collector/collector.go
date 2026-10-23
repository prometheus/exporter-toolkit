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

// Package collector provides a common registry for exporter collectors: the
// `--collector.<name>` / `--no-collector.<name>` flag convention, the
// enabled/disabled state behind it, and a machine-readable view of both.
//
// The registry deliberately knows nothing about what a collector does. It is
// generic over the collector type C and the factory config type Cfg, so each
// exporter keeps its own collector interface:
//
//	node_exporter:     Update(ch chan<- prometheus.Metric) error
//	postgres_exporter: Update(ctx, instance, ch chan<- prometheus.Metric) error
//
// What the registry owns is everything those exporters currently duplicate
// verbatim: flag registration, forced-state tracking, scrape-time filters, and
// lazy instantiation with caching.
package collector

import (
	"fmt"
	"maps"
	"slices"
	"strconv"
	"sync"

	"github.com/alecthomas/kingpin/v2"
)

// Descriptor is the operator-facing description of a collector. It is the unit
// of introspection: everything an exporter can say about a collector without
// running it lives here, which is what makes documentation generation fall out
// of the registry rather than being maintained alongside it.
type Descriptor struct {
	// Name is the collector name as it appears in `--collector.<name>`.
	Name string `json:"name"`

	// Help is a one-line description of what the collector scrapes.
	Help string `json:"help,omitempty"`

	// DefaultEnabled reports whether the collector runs when the operator
	// passes no flag for it.
	DefaultEnabled bool `json:"default_enabled"`

	// Requires lists preconditions the operator has to satisfy for the
	// collector to return data, e.g. "pg_stat_statements extension" or
	// "PostgreSQL 17+". Purely informational; the registry does not check it.
	Requires []string `json:"requires,omitempty"`
}

func (d Descriptor) defaultState() string {
	if d.DefaultEnabled {
		return "enabled"
	}
	return "disabled"
}

type flagGroup interface {
	Flag(string, string) *kingpin.FlagClause
}

// StaticConfig adapts a config value that is the same for every collector into
// the function Build expects.
func StaticConfig[Cfg any](cfg Cfg) func(string) Cfg {
	return func(string) Cfg { return cfg }
}

// Registry tracks the collectors an exporter has, which of them are enabled,
// and how to build them.
//
// C is the exporter's collector interface. Cfg is whatever that exporter's
// factories need in order to construct one (a logger, a DB handle, options).
type Registry[C any, Cfg any] struct {
	namespace string

	mtx        sync.Mutex
	entries    map[string]*entry[C, Cfg]
	flagsAdded bool
}

type entry[C any, Cfg any] struct {
	desc     Descriptor
	factory  func(Cfg) (C, error)
	enabled  bool
	forced   bool
	built    bool
	instance C
}

// NewRegistry returns an empty Registry. The namespace is used to prefix any
// metrics the registry exposes about itself (see EnabledMetrics).
func NewRegistry[C any, Cfg any](namespace string) *Registry[C, Cfg] {
	return &Registry[C, Cfg]{
		namespace: namespace,
		entries:   make(map[string]*entry[C, Cfg]),
	}
}

// Register adds a collector to the registry. It is intended to be called from
// an init() function, the way exporters register collectors today.
//
// Register panics on a duplicate name or on registration after AddFlags, both
// of which are programmer errors that would otherwise surface as a silently
// missing collector.
func (r *Registry[C, Cfg]) Register(d Descriptor, factory func(Cfg) (C, error)) {
	r.mtx.Lock()
	defer r.mtx.Unlock()

	if d.Name == "" {
		panic("collector: Register called with an empty Descriptor.Name")
	}
	if _, dup := r.entries[d.Name]; dup {
		panic(fmt.Sprintf("collector: duplicate registration for %q", d.Name))
	}
	if r.flagsAdded {
		panic(fmt.Sprintf("collector: %q registered after AddFlags", d.Name))
	}

	r.entries[d.Name] = &entry[C, Cfg]{desc: d, factory: factory, enabled: d.DefaultEnabled}
}

// AddFlags registers the `--collector.<name>` / `--no-collector.<name>` flag
// pair for every registered collector to a kingpin Application or CmdClause.
// Call it once, from main, before parsing.
func (r *Registry[C, Cfg]) AddFlags(app flagGroup) {
	r.mtx.Lock()
	defer r.mtx.Unlock()

	r.flagsAdded = true
	for _, name := range slices.Sorted(maps.Keys(r.entries)) {
		e := r.entries[name]

		help := e.desc.Help
		if help == "" {
			help = fmt.Sprintf("Enable the %s collector", name)
		}

		app.Flag(fmt.Sprintf("collector.%s", name), fmt.Sprintf("%s (default: %s).", help, e.desc.defaultState())).
			Default(strconv.FormatBool(e.desc.DefaultEnabled)).
			Action(r.forceAction(e)).
			BoolVar(&e.enabled)
	}
}

// forceAction records that an operator named this collector on the command
// line, so DisableDefaults can leave explicit choices alone.
//
// A distinct closure per collector is required because kingpin's ParseContext
// does not identify which flag invoked the action.
// See: https://github.com/alecthomas/kingpin/issues/294
func (r *Registry[C, Cfg]) forceAction(e *entry[C, Cfg]) func(*kingpin.ParseContext) error {
	return func(*kingpin.ParseContext) error {
		r.mtx.Lock()
		defer r.mtx.Unlock()
		e.forced = true
		return nil
	}
}

// DisableDefaults turns off every collector the operator did not explicitly
// name on the command line. It backs the conventional
// `--collector.disable-defaults` flag.
func (r *Registry[C, Cfg]) DisableDefaults() {
	r.mtx.Lock()
	defer r.mtx.Unlock()

	for _, e := range r.entries {
		if !e.forced {
			e.enabled = false
		}
	}
}

// SetEnabled overrides a collector's state programmatically and marks it as
// explicitly chosen, so a later DisableDefaults will not clear it. It exists
// for exporters that resolve collector state from a config file as well as
// from flags.
func (r *Registry[C, Cfg]) SetEnabled(name string, enabled bool) error {
	r.mtx.Lock()
	defer r.mtx.Unlock()

	e, ok := r.entries[name]
	if !ok {
		return fmt.Errorf("unknown collector: %s", name)
	}
	e.enabled = enabled
	e.forced = true
	return nil
}

// IsEnabled reports whether a collector will run. Unknown names report false.
func (r *Registry[C, Cfg]) IsEnabled(name string) bool {
	r.mtx.Lock()
	defer r.mtx.Unlock()

	e, ok := r.entries[name]
	return ok && e.enabled
}

// Descriptors returns every registered collector, enabled or not, sorted by
// name. This is the input to documentation generation.
func (r *Registry[C, Cfg]) Descriptors() []Descriptor {
	r.mtx.Lock()
	defer r.mtx.Unlock()

	out := make([]Descriptor, 0, len(r.entries))
	for _, name := range slices.Sorted(maps.Keys(r.entries)) {
		out = append(out, r.entries[name].desc)
	}
	return out
}

// Enabled returns the names of the collectors that will run, sorted. This is
// the runtime question — what is this process actually scraping — answered the
// same way for every exporter.
func (r *Registry[C, Cfg]) Enabled() []string {
	r.mtx.Lock()
	defer r.mtx.Unlock()

	var out []string
	for name, e := range r.entries {
		if e.enabled {
			out = append(out, name)
		}
	}
	slices.Sort(out)
	return out
}

// Build instantiates the enabled collectors and returns them keyed by name.
// Instances are cached, so repeated calls reuse collectors that hold state or
// open handles.
//
// cfgFor produces the config for one collector. It takes the collector name
// because exporters routinely specialize per collector — both node_exporter and
// postgres_exporter pass a logger scoped with `logger.With("collector", name)`.
// Use StaticConfig if the config does not vary.
//
// If filters is non-empty, only those collectors are built; a filter naming an
// unknown or disabled collector is an error. This backs the `collect[]` scrape
// parameter.
func (r *Registry[C, Cfg]) Build(cfgFor func(name string) Cfg, filters ...string) (map[string]C, error) {
	r.mtx.Lock()
	defer r.mtx.Unlock()

	names := filters
	for _, f := range filters {
		e, ok := r.entries[f]
		if !ok {
			return nil, fmt.Errorf("missing collector: %s", f)
		}
		if !e.enabled {
			return nil, fmt.Errorf("disabled collector: %s", f)
		}
	}
	if len(filters) == 0 {
		names = make([]string, 0, len(r.entries))
		for name, e := range r.entries {
			if e.enabled {
				names = append(names, name)
			}
		}
	}

	out := make(map[string]C, len(names))
	for _, name := range names {
		e := r.entries[name]
		if !e.built {
			c, err := e.factory(cfgFor(name))
			if err != nil {
				return nil, fmt.Errorf("couldn't create collector %s: %w", name, err)
			}
			e.instance, e.built = c, true
		}
		out[name] = e.instance
	}
	return out, nil
}
