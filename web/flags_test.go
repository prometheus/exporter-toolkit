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
	"os"
	"runtime"
	"strconv"
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

// TestSystemdSocketsPassed checks that the systemd socket activation listeners
// are used when systemd passed sockets to this process, even without the flag.
func TestSystemdSocketsPassed(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("socket activation is only available on Linux")
	}
	flags := &FlagConfig{
		WebSystemdSocket: new(false),
		WebConfigFile:    new(""),
	}

	t.Setenv("LISTEN_FDS", "1")
	t.Setenv("LISTEN_PID", strconv.Itoa(os.Getpid()))
	if !flags.useSystemdSocket() {
		t.Error("useSystemdSocket() = false with sockets passed to this process, want true")
	}
	if err := flags.checkFlags(); err != nil {
		t.Errorf("checkFlags() = %v without listen addresses and with sockets passed, want nil", err)
	}

	t.Setenv("LISTEN_PID", strconv.Itoa(os.Getpid()+1))
	if flags.useSystemdSocket() {
		t.Error("useSystemdSocket() = true with sockets passed to another process, want false")
	}

	t.Setenv("LISTEN_PID", strconv.Itoa(os.Getpid()))
	t.Setenv("LISTEN_FDS", "")
	if flags.useSystemdSocket() {
		t.Error("useSystemdSocket() = true without LISTEN_FDS, want false")
	}
}
