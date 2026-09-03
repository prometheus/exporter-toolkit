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

package web

import (
	"errors"
	"net"
	"net/http"
	"testing"
)

func testListener(t *testing.T) net.Listener {
	t.Helper()
	l, err := net.Listen("tcp", "localhost:0")
	if err != nil {
		t.Fatalf("Unable to listen: %v", err)
	}
	t.Cleanup(func() { l.Close() })
	return l
}

// TestServeRejectsIncompleteFlagConfig checks that Serve and ServeMultiple
// report an incomplete FlagConfig instead of dereferencing a nil field. They
// are exported for callers that create their own listeners, and those callers
// build a FlagConfig by hand rather than getting one from kingpinflag.
func TestServeRejectsIncompleteFlagConfig(t *testing.T) {
	for _, tc := range []struct {
		name  string
		flags *FlagConfig
	}{
		{name: "nil FlagConfig", flags: nil},
		{name: "no WebConfigFile", flags: &FlagConfig{}},
		{name: "no WebConfigFile with listen addresses", flags: &FlagConfig{
			WebListenAddresses: &[]string{"localhost:0"},
			WebSystemdSocket:   OfBool(false),
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Run("Serve", func(t *testing.T) {
				err := Serve(testListener(t), &http.Server{}, tc.flags, testlogger)
				if !errors.Is(err, ErrMissingFlag) {
					t.Errorf("Serve() = %v, expected %v", err, ErrMissingFlag)
				}
			})
			t.Run("ServeMultiple", func(t *testing.T) {
				err := ServeMultiple([]net.Listener{testListener(t)}, &http.Server{}, tc.flags, testlogger)
				if !errors.Is(err, ErrMissingFlag) {
					t.Errorf("ServeMultiple() = %v, expected %v", err, ErrMissingFlag)
				}
			})
		})
	}
}

// TestServeDoesNotRequireListenAddresses checks that Serve accepts a
// FlagConfig without listener fields. The caller passes the listener in, so
// requiring them would reject a legitimate configuration.
func TestServeDoesNotRequireListenAddresses(t *testing.T) {
	if err := (&FlagConfig{WebConfigFile: OfString("")}).checkWebConfigFlag(); err != nil {
		t.Errorf("checkWebConfigFlag() = %v, expected nil", err)
	}
}

// TestCheckFlagsStillRequiresListeners checks that the listener requirement is
// unchanged for ListenAndServe, which does create the listeners.
func TestCheckFlagsStillRequiresListeners(t *testing.T) {
	flags := &FlagConfig{WebConfigFile: OfString("")}
	if err := flags.checkFlags(); !errors.Is(err, ErrNoListeners) {
		t.Errorf("checkFlags() = %v, expected %v", err, ErrNoListeners)
	}
}
