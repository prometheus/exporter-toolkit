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
				WebSystemdSocket:   OfBool(false),
			},
			want: ErrMissingFlag,
		},
		{
			name: "listen addresses only",
			flags: &FlagConfig{
				WebListenAddresses: &[]string{":9100"},
				WebConfigFile:      OfString(""),
			},
			want: nil,
		},
		{
			name: "systemd socket activation enabled without listen addresses",
			flags: &FlagConfig{
				WebSystemdSocket: OfBool(true),
				WebConfigFile:    OfString(""),
			},
			want: nil,
		},
		// Regression test: a non-nil but false systemd socket flag used to
		// satisfy checkFlags, so ListenAndServe went on to dereference the nil
		// WebListenAddresses and panicked.
		{
			name: "systemd socket activation disabled with nil listen addresses",
			flags: &FlagConfig{
				WebSystemdSocket: OfBool(false),
				WebConfigFile:    OfString(""),
			},
			want: ErrNoListeners,
		},
		{
			name: "systemd socket activation disabled with empty listen addresses",
			flags: &FlagConfig{
				WebListenAddresses: &[]string{},
				WebSystemdSocket:   OfBool(false),
				WebConfigFile:      OfString(""),
			},
			want: ErrNoListeners,
		},
		{
			name: "no listeners configured at all",
			flags: &FlagConfig{
				WebConfigFile: OfString(""),
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
		WebSystemdSocket: OfBool(false),
		WebConfigFile:    OfString(""),
	}
	if err := ListenAndServe(nil, flags, testlogger); !errors.Is(err, ErrNoListeners) {
		t.Fatalf("ListenAndServe() = %v, want %v", err, ErrNoListeners)
	}
}
