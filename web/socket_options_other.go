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

//go:build !linux && !freebsd && !darwin && !dragonfly && !netbsd && !openbsd

package web

import (
	"log/slog"
	"sync"
	"syscall"
)

var warnSocketOptionsUnsupportedOnce sync.Once

func warnOnceIfConfigured(opts socketOptions) {
	if opts.anySet() {
		warnSocketOptionsUnsupportedOnce.Do(func() {
			slog.Default().Warn("IP socket options (TTL/hop-limit/DSCP) are not supported on this platform; configured values will be ignored")
		})
	}
}

// applyListenerOptions is a no-op on platforms without unix.SetsockoptInt
// support. The first time it sees configured options it emits a single
// warn-level log line; subsequent calls are silent.
func applyListenerOptions(_ syscall.RawConn, opts socketOptions) error {
	warnOnceIfConfigured(opts)
	return nil
}

// applyConnOptions mirrors applyListenerOptions: no-op + one-shot warning.
func applyConnOptions(_ syscall.RawConn, opts socketOptions) error {
	warnOnceIfConfigured(opts)
	return nil
}
