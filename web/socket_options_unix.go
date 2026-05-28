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

//go:build linux || freebsd || darwin || dragonfly || netbsd || openbsd

package web

import (
	"errors"
	"fmt"
	"syscall"

	"golang.org/x/sys/unix"
)

// applyListenerOptions sets the IP socket options that are *inherited* by
// accepted connections on Linux: IP_TTL and IPV6_UNICAST_HOPS. These belong
// on the listening socket so the SYN-ACK and every subsequent packet on an
// accepted connection carries the configured value. DSCP is NOT inherited
// and is applied per-accepted-connection by applyConnOptions instead.
func applyListenerOptions(c syscall.RawConn, opts socketOptions) error {
	if opts.IPv4TTL == 0 && opts.IPv6HopLimit == 0 {
		return nil
	}
	var setErr error
	ctrlErr := c.Control(func(fd uintptr) {
		if opts.IPv4TTL > 0 {
			if err := setIfApplicable(fd, unix.IPPROTO_IP, unix.IP_TTL, int(opts.IPv4TTL), "IP_TTL"); err != nil {
				setErr = err
				return
			}
		}
		if opts.IPv6HopLimit > 0 {
			if err := setIfApplicable(fd, unix.IPPROTO_IPV6, unix.IPV6_UNICAST_HOPS, int(opts.IPv6HopLimit), "IPV6_UNICAST_HOPS"); err != nil {
				setErr = err
				return
			}
		}
	})
	if ctrlErr != nil {
		return ctrlErr
	}
	return setErr
}

// applyConnOptions sets the IP socket options that are NOT inherited by
// accepted connections and so must be applied per-connection: IP_TOS and
// IPV6_TCLASS (the DSCP codepoint shifted into the upper 6 bits).
//
// The 2 ECN bits (lower 2 bits of the ToS / Traffic Class byte) are
// deliberately not touched -- the kernel manages them per-packet for
// ECN-capable TCP connections (RFC 3168).
func applyConnOptions(c syscall.RawConn, opts socketOptions) error {
	if opts.DSCP < 0 {
		return nil
	}
	tos := opts.DSCP << 2
	var setErr error
	ctrlErr := c.Control(func(fd uintptr) {
		if err := setIfApplicable(fd, unix.IPPROTO_IP, unix.IP_TOS, tos, "IP_TOS"); err != nil {
			setErr = err
			return
		}
		if err := setIfApplicable(fd, unix.IPPROTO_IPV6, unix.IPV6_TCLASS, tos, "IPV6_TCLASS"); err != nil {
			setErr = err
			return
		}
	})
	if ctrlErr != nil {
		return ctrlErr
	}
	return setErr
}

// setIfApplicable calls setsockopt, swallowing ENOPROTOOPT so we can try
// both v4 and v6 options on a socket without first inspecting its family
// (matters for dual-stack listeners on [::]:port).
func setIfApplicable(fd uintptr, level, opt, value int, name string) error {
	err := unix.SetsockoptInt(int(fd), level, opt, value)
	if err == nil {
		return nil
	}
	if errors.Is(err, unix.ENOPROTOOPT) {
		return nil
	}
	return fmt.Errorf("setsockopt %s=%d: %w", name, value, err)
}
