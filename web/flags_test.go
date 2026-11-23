// Copyright 2025 The Prometheus Authors
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

package web

import (
	"errors"
	"net"
	"net/http"
	"testing"
)

func TestCheckFlags(t *testing.T) {
	for _, tc := range []struct {
		name  string
		flags *FlagConfig
		want  error
	}{
		{
			name:  "nil FlagConfig",
			flags: nil,
			want:  ErrMissingFlag,
		},
		{
			name: "missing web config file",
			flags: &FlagConfig{
				WebListenAddresses: &[]string{":9100"},
				WebSystemdSocket:   new(false),
			},
			want: ErrMissingFlag,
		},
		{
			name: "listen addresses only",
			flags: &FlagConfig{
				WebListenAddresses: &[]string{":9100"},
				WebConfigFile:      new(""),
			},
			want: nil,
		},
		{
			name: "systemd socket activation enabled without listen addresses",
			flags: &FlagConfig{
				WebSystemdSocket: new(true),
				WebConfigFile:    new(""),
			},
			want: nil,
		},
		// Regression test: a non-nil but false systemd socket flag used to
		// satisfy checkFlags, so ListenAndServe went on to dereference the nil
		// WebListenAddresses and panicked.
		{
			name: "systemd socket activation disabled with nil listen addresses",
			flags: &FlagConfig{
				WebSystemdSocket: new(false),
				WebConfigFile:    new(""),
			},
			want: ErrNoListeners,
		},
		{
			name: "systemd socket activation disabled with empty listen addresses",
			flags: &FlagConfig{
				WebListenAddresses: &[]string{},
				WebSystemdSocket:   new(false),
				WebConfigFile:      new(""),
			},
			want: ErrNoListeners,
		},
		{
			name: "no listeners configured at all",
			flags: &FlagConfig{
				WebConfigFile: new(""),
			},
			want: ErrNoListeners,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := tc.flags.checkFlags(); !errors.Is(err, tc.want) {
				t.Fatalf("checkFlags() = %v, want %v", err, tc.want)
			}
		})
	}
}

// TestListenAndServeNoListeners checks that ListenAndServe reports a missing
// listener configuration instead of panicking on a nil WebListenAddresses.
func TestListenAndServeNoListeners(t *testing.T) {
	flags := &FlagConfig{
		WebSystemdSocket: new(false),
		WebConfigFile:    new(""),
	}
	if err := ListenAndServe(nil, flags, testlogger); !errors.Is(err, ErrNoListeners) {
		t.Fatalf("ListenAndServe() = %v, want %v", err, ErrNoListeners)
	}
}

// TestServeRejectsIncompleteFlagConfig checks that Serve and ServeMultiple
// report an incomplete FlagConfig instead of dereferencing a nil field. They
// are exported for callers that create their own listeners, and those callers
// build a FlagConfig by hand rather than getting one from kingpinflag. The
// listeners are nil because the flag check fails before they are used.
func TestServeRejectsIncompleteFlagConfig(t *testing.T) {
	for _, tc := range []struct {
		name  string
		flags *FlagConfig
	}{
		{name: "nil FlagConfig", flags: nil},
		{name: "no WebConfigFile", flags: &FlagConfig{}},
		{name: "no WebConfigFile with listen addresses", flags: &FlagConfig{
			WebListenAddresses: &[]string{"localhost:0"},
			WebSystemdSocket:   new(false),
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := Serve(nil, &http.Server{}, tc.flags, testlogger); !errors.Is(err, ErrMissingFlag) {
				t.Errorf("Serve() = %v, want %v", err, ErrMissingFlag)
			}
			if err := ServeMultiple(make([]net.Listener, 1), &http.Server{}, tc.flags, testlogger); !errors.Is(err, ErrMissingFlag) {
				t.Errorf("ServeMultiple() = %v, want %v", err, ErrMissingFlag)
			}
		})
	}
}

// TestServeDoesNotRequireListenAddresses checks that Serve and ServeMultiple
// accept a FlagConfig without listener fields. The caller passes the listener
// in, so requiring them would reject a legitimate configuration. It goes
// through configureServer, the setup both share, because serving would block.
func TestServeDoesNotRequireListenAddresses(t *testing.T) {
	if _, err := configureServer(&http.Server{}, &FlagConfig{WebConfigFile: new("")}, testlogger); err != nil {
		t.Errorf("configureServer() = %v, want nil", err)
	}
}
