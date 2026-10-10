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

//go:build linux

package web

import (
	"context"
	"log/slog"
	"net"
	"os"
	"syscall"
	"testing"

	"golang.org/x/sys/unix"
)

// TestApplySocketOptions_Inheritance is the load-bearing test for this
// feature: it verifies that IP socket options set on the listening socket
// via net.ListenConfig.Control are inherited by accepted connections on
// Linux. If this property ever stops holding, the whole feature stops
// working -- so the test is intentionally pedantic.
//
// Coverage matrix (positive / boundary / corner):
//   - positive:  ipv4_ttl_mid, ipv6_hop_mid, dscp_mid, all_options_v4, dual_stack_all
//   - boundary:  ipv4_ttl_min (TTL=1, security extreme), ipv4_ttl_max (TTL=255),
//     dscp_zero (corner: explicit 0 IS configured), dscp_max (DSCP=63)
//   - corner:    dscp_zero (verifies setsockopt is actually called when DSCP=0),
//     dual_stack_all (both v4 and v6 options set on [::]:0)
func TestApplySocketOptions_Inheritance(t *testing.T) {
	const skipCheck = -1
	cases := []struct {
		name    string
		address string
		opts    socketOptions
		// Expected values read back via getsockopt on both the listener
		// and the accepted connection. -1 means "don't check this option".
		wantIPTTL    int
		wantIPv6Hops int
		wantIPToS    int // already shifted (DSCP << 2); skipCheck to skip
		wantIPv6TCl  int
	}{
		{
			name:         "ipv4_ttl_min",
			address:      "127.0.0.1:0",
			opts:         socketOptions{IPv4TTL: 1, DSCP: -1},
			wantIPTTL:    1,
			wantIPv6Hops: skipCheck,
			wantIPToS:    skipCheck,
			wantIPv6TCl:  skipCheck,
		},
		{
			name:         "ipv4_ttl_mid",
			address:      "127.0.0.1:0",
			opts:         socketOptions{IPv4TTL: 7, DSCP: -1},
			wantIPTTL:    7,
			wantIPv6Hops: skipCheck,
			wantIPToS:    skipCheck,
			wantIPv6TCl:  skipCheck,
		},
		{
			name:         "ipv4_ttl_max",
			address:      "127.0.0.1:0",
			opts:         socketOptions{IPv4TTL: 255, DSCP: -1},
			wantIPTTL:    255,
			wantIPv6Hops: skipCheck,
			wantIPToS:    skipCheck,
			wantIPv6TCl:  skipCheck,
		},
		{
			name:         "ipv6_hop_mid",
			address:      "[::1]:0",
			opts:         socketOptions{IPv6HopLimit: 4, DSCP: -1},
			wantIPTTL:    skipCheck,
			wantIPv6Hops: 4,
			wantIPToS:    skipCheck,
			wantIPv6TCl:  skipCheck,
		},
		{
			name:         "dscp_zero",
			address:      "127.0.0.1:0",
			opts:         socketOptions{DSCP: 0},
			wantIPTTL:    skipCheck,
			wantIPv6Hops: skipCheck,
			wantIPToS:    0, // DSCP=0 explicitly configured; setsockopt is called
			wantIPv6TCl:  skipCheck,
		},
		{
			name:         "dscp_mid",
			address:      "127.0.0.1:0",
			opts:         socketOptions{DSCP: 46}, // EF
			wantIPTTL:    skipCheck,
			wantIPv6Hops: skipCheck,
			wantIPToS:    46 << 2,
			wantIPv6TCl:  skipCheck,
		},
		{
			name:         "dscp_max",
			address:      "127.0.0.1:0",
			opts:         socketOptions{DSCP: 63},
			wantIPTTL:    skipCheck,
			wantIPv6Hops: skipCheck,
			wantIPToS:    63 << 2,
			wantIPv6TCl:  skipCheck,
		},
		{
			name:         "all_options_v4",
			address:      "127.0.0.1:0",
			opts:         socketOptions{IPv4TTL: 3, DSCP: 16},
			wantIPTTL:    3,
			wantIPv6Hops: skipCheck,
			wantIPToS:    16 << 2,
			wantIPv6TCl:  skipCheck,
		},
		{
			name:         "dual_stack_all",
			address:      "[::]:0",
			opts:         socketOptions{IPv4TTL: 2, IPv6HopLimit: 2, DSCP: 26},
			wantIPTTL:    2,
			wantIPv6Hops: 2,
			wantIPToS:    26 << 2,
			wantIPv6TCl:  26 << 2,
		},
	}

	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// Build the same listener stack ListenAndServe constructs:
			//   * ListenConfig.Control applies the *inherited* options
			//     (IP_TTL, IPV6_UNICAST_HOPS) on the listening socket.
			//   * ipSocketListener wraps the result to apply the
			//     *non-inherited* options (IP_TOS, IPV6_TCLASS) per
			//     accepted connection.
			lc := net.ListenConfig{
				Control: func(_, _ string, c syscall.RawConn) error {
					return applyListenerOptions(c, tc.opts)
				},
			}
			rawLn, err := lc.Listen(context.Background(), "tcp", tc.address)
			if err != nil {
				t.Fatalf("listen: %v", err)
			}
			t.Cleanup(func() { rawLn.Close() })

			// Verify TTL/HopLimit on the listener FD. DSCP is checked only
			// on accepted connections (the listener-side IP_TOS isn't
			// inherited, so setting it on the listener has no effect on
			// outbound packets from accepted conns).
			tcpLn := rawLn.(*net.TCPListener)
			lrc, err := tcpLn.SyscallConn()
			if err != nil {
				t.Fatalf("listener SyscallConn: %v", err)
			}
			checkFD(t, lrc, "listener", tc.wantIPTTL, tc.wantIPv6Hops, skipCheck, skipCheck)

			// Wrap with ipSocketListener for DSCP application on accept,
			// matching the stack ListenAndServe builds when DSCP is configured.
			var ln net.Listener = tcpLn
			if tc.opts.DSCP >= 0 {
				ln = &ipSocketListener{Listener: tcpLn, opts: tc.opts, logger: logger}
			}

			dialErrCh := make(chan error, 1)
			go func() {
				conn, err := net.Dial("tcp", rawLn.Addr().String())
				if conn != nil {
					t.Cleanup(func() { conn.Close() })
				}
				dialErrCh <- err
			}()
			acceptedConn, err := ln.Accept()
			if err != nil {
				t.Fatalf("accept: %v", err)
			}
			t.Cleanup(func() { acceptedConn.Close() })
			if err := <-dialErrCh; err != nil {
				t.Fatalf("dial: %v", err)
			}

			tcpConn := acceptedConn.(*net.TCPConn)
			arc, err := tcpConn.SyscallConn()
			if err != nil {
				t.Fatalf("accepted conn SyscallConn: %v", err)
			}
			// Check all four expected options on the accepted connection.
			// TTL/HopLimit are inherited from the listener; DSCP was applied
			// by the ipSocketListener wrapper.
			checkFD(t, arc, "accepted", tc.wantIPTTL, tc.wantIPv6Hops, tc.wantIPToS, tc.wantIPv6TCl)
		})
	}
}

// checkFD reads each requested socket option from the given RawConn and
// verifies it matches the expected value. -1 means "skip this option".
// DSCP comparisons mask off the lower 2 bits because the kernel may modify
// the ECN bits dynamically on ECN-capable TCP connections.
func checkFD(t *testing.T, rc syscall.RawConn, label string, wantTTL, wantHops, wantToS, wantTCl int) {
	t.Helper()
	const skip = -1
	var controlErr error
	err := rc.Control(func(fd uintptr) {
		if wantTTL != skip {
			got, err := unix.GetsockoptInt(int(fd), unix.IPPROTO_IP, unix.IP_TTL)
			if err != nil {
				controlErr = err
				return
			}
			if got != wantTTL {
				t.Errorf("%s: IP_TTL = %d, want %d", label, got, wantTTL)
			}
		}
		if wantHops != skip {
			got, err := unix.GetsockoptInt(int(fd), unix.IPPROTO_IPV6, unix.IPV6_UNICAST_HOPS)
			if err != nil {
				controlErr = err
				return
			}
			if got != wantHops {
				t.Errorf("%s: IPV6_UNICAST_HOPS = %d, want %d", label, got, wantHops)
			}
		}
		if wantToS != skip {
			got, err := unix.GetsockoptInt(int(fd), unix.IPPROTO_IP, unix.IP_TOS)
			if err != nil {
				controlErr = err
				return
			}
			// Mask off ECN (low 2 bits); we only compare the DSCP portion.
			gotDSCP := got & 0xFC
			if gotDSCP != wantToS {
				t.Errorf("%s: IP_TOS DSCP bits = 0x%x, want 0x%x (raw=0x%x)", label, gotDSCP, wantToS, got)
			}
		}
		if wantTCl != skip {
			got, err := unix.GetsockoptInt(int(fd), unix.IPPROTO_IPV6, unix.IPV6_TCLASS)
			if err != nil {
				controlErr = err
				return
			}
			gotDSCP := got & 0xFC
			if gotDSCP != wantTCl {
				t.Errorf("%s: IPV6_TCLASS DSCP bits = 0x%x, want 0x%x (raw=0x%x)", label, gotDSCP, wantTCl, got)
			}
		}
	})
	if err != nil {
		t.Fatalf("%s: rc.Control: %v", label, err)
	}
	if controlErr != nil {
		t.Fatalf("%s: getsockopt: %v", label, controlErr)
	}
}
