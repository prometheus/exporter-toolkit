# Design Brief: Configurable IP Socket Options (TTL, Hop Limit, DSCP) for `web.ListenAndServe`

Status: Draft — pre-PR design brief
Author: dave.seddon.ca@gmail.com
Branch: `ttl` (fork: `randomizedcoder/exporter-toolkit`)
Companion doc: [`node_exporter:docs/IP_SOCKET_CONFIG.md`](https://github.com/randomizedcoder/node_exporter/blob/ttl/docs/IP_SOCKET_CONFIG.md) (security/QoS rationale and exporter-side perspective)

## Introduction

This brief proposes adding configurable IP-layer header fields — IPv4 TTL, IPv6 Hop Limit, and DSCP (applied uniformly to IPv4 ToS and IPv6 Traffic Class) — to the listening sockets created by `github.com/prometheus/exporter-toolkit/web`. Two motivations:

1. **Security via TTL clamping.** TTL=2 means packets die after two router hops; the exporter cannot leak metric data beyond the immediate L3 neighborhood even if firewalls or ACLs misbehave.
2. **QoS via DSCP marking.** Operators on networks with traffic shaping or differentiated services need to classify scrape traffic with a specific codepoint (CS2, AF11, EF, etc.) so intermediate equipment queues it correctly.

All three knobs touch the IP header on the same socket via the same `net.ListenConfig.Control` chokepoint with the same `setsockopt` pattern and the same Linux inheritance semantics on accepted connections. Bundling them in one feature is natural; landing it here propagates to every toolkit-using exporter.

## Table of contents

- [Introduction](#introduction)
- [Background](#background)
- [Configuration surface](#configuration-surface)
- [Step 1 — Config plumbing](#step-1--config-plumbing)
- [Step 2 — Socket-control function](#step-2--socket-control-function)
- [Step 3 — Wire into `ListenAndServe`](#step-3--wire-into-listenandserve)
- [Step 4 — Tests](#step-4--tests)
- [Step 5 — Documentation](#step-5--documentation)
- [Step 6 — Platform support and edge cases](#step-6--platform-support-and-edge-cases)
- [Summary](#summary)

## Background

`ListenAndServe` in `web/tls_config.go` creates the TCP listener via a bare `net.Listen("tcp", address)` at line 323. Go's standard library exposes the listening socket's file descriptor before `bind(2)` via `net.ListenConfig.Control`; calling `unix.SetsockoptInt` at that point sets options on the listening socket. On Linux, the relevant options — `IP_TTL`, `IP_TOS`, `IPV6_UNICAST_HOPS`, `IPV6_TCLASS` — are all inherited by sockets returned from `accept(2)`, including the SYN-ACK packet (`accept(2)`, `ip(7)`, `ipv6(7)`). `tls.NewListener` is a transparent wrapper, so the settings flow through TLS unchanged.

**TTL/Hop Limit semantics.** RFC 1122 §3.2.1.7 forbids hosts from sending datagrams with TTL=0. On Linux, `setsockopt(IP_TTL, 0)` is overloaded to mean "use the kernel default", not "send literal zero". The minimum useful configured TTL is therefore **1** (packet dies at the first router; same-L2 reach only). This design treats values 1–255 as configured TTLs and reserves `0` as the "not configured" sentinel. We use Go type `uint8` for these knobs: it exactly matches the wire field, makes negative values a compile-time impossibility (removing a whole class of bug-or-validation), and the sentinel `0` is the one `uint8` value that's invalid as a configured TTL anyway. A small `int(value)` cast bridges to `unix.SetsockoptInt` at the syscall boundary.

**DSCP semantics.** RFC 2474 / 3260 define the ToS / Traffic Class byte as DSCP in the upper 6 bits and ECN in the lower 2 bits. `setsockopt(IP_TOS, d << 2)` sets a persistent DSCP `d` while the kernel continues to manage ECN bits per packet for ECN-capable TCP connections. **DSCP=0 (CS0) is a valid configured value**, so the "not configured" sentinel must live outside the value range — `-1` (Go type `int`) is the natural choice. We accept the asymmetry with TTL/Hop Limit (`uint8` vs `int`) because each type matches its own semantics; forcing both to `uint8` would mean picking an awkward in-band sentinel like `255` for DSCP.

Two listener flavors need bespoke treatment:

- **VSOCK** (`web/tls_config.go:316–321`): no IP layer; all three options are meaningless. Log-and-skip.
- **Systemd socket activation** (`web/tls_config.go:297–306`): listeners come pre-bound from `activation.Listeners()`, so `ListenConfig.Control` doesn't apply. Options are set post-bind via `(*net.TCPListener).File()` + `unix.SetsockoptInt` on the duplicated FD.

The toolkit's `go.mod` already requires `golang.org/x/sys` (indirect, v0.44.0). Promote to a direct dep.

## Configuration surface

Three input layers with precedence **flag > env var > YAML > default**:

| Knob | Flag | Env var | YAML field | Configured range | Sentinel (not configured) |
|---|---|---|---|---|---|
| IPv4 TTL | `--web.ipv4-ttl` | `WEB_IPV4_TTL` | `ip_socket_config.ipv4_ttl` | 1–255 | flag `0`; YAML absent |
| IPv6 Hop Limit | `--web.ipv6-hop-limit` | `WEB_IPV6_HOP_LIMIT` | `ip_socket_config.ipv6_hop_limit` | 1–255 | flag `0`; YAML absent |
| DSCP | `--web.dscp` | `WEB_DSCP` | `ip_socket_config.dscp` | 0–63 | flag `-1`; YAML absent |

**Validation** at config-load time:

- TTL / Hop Limit: 1–255; explicit `0` via YAML is rejected (use omission instead). `0` via flag is the sentinel and silently means "not configured".
- DSCP: 0–63; `-1` via flag is the sentinel; out-of-range values rejected with a clear error citing the config file path.

YAML fields use `*int` so "absent" is distinguishable from "explicit zero" (load-bearing for DSCP).

## Step 1 — Config plumbing

In `web/tls_config.go`:

- `FlagConfig` (around line 68): add `WebIPv4TTL *uint8`, `WebIPv6HopLimit *uint8`, `WebDSCP *int`. Types chosen so TTL/Hop-Limit can never go negative; DSCP needs `int` because 0 is valid and we want `-1` as the "not configured" sentinel.
- Top-level `Config` (around line 45): add `IPSocketConfig IPSocketConfig \`yaml:"ip_socket_config"\``.
- New struct (pointer fields so YAML absent ≠ explicit zero):

```go
type IPSocketConfig struct {
    IPv4TTL      *uint8 `yaml:"ipv4_ttl"`
    IPv6HopLimit *uint8 `yaml:"ipv6_hop_limit"`
    DSCP         *int   `yaml:"dscp"`
}
```

- `getConfig()` (around line 119) validates non-nil fields; errors include the config file path.

In `web/kingpinflag/flag.go` (around line 28): register three flags with `.Envar(...)` and the appropriate sentinel defaults (`0` for TTL fields, `-1` for DSCP).

Precedence helper in `tls_config.go` — generic so the `*uint8` (TTL/Hop-Limit) and `*int` (DSCP) call sites share one implementation:

```go
func effective[T comparable](flagVal *T, flagSentinel T, yamlVal *T) (T, bool) {
    var zero T
    if flagVal != nil && *flagVal != flagSentinel {
        return *flagVal, true
    }
    if yamlVal != nil {
        return *yamlVal, true
    }
    return zero, false
}
```

### Definition of done — Step 1

- [ ] `FlagConfig` exposes three new `*int` fields with correct sentinel defaults.
- [ ] `Config` exposes `IPSocketConfig` with `*int` YAML-tagged fields.
- [ ] `kingpinflag.AddFlags` registers three flags with env-var fallback.
- [ ] `getConfig()` validates ranges; errors cite the config file path.
- [ ] `effective` consolidates precedence in one place.

## Step 2 — Socket-control function

Three platform-split files in `web/`:

- `socket_options_linux.go` (`//go:build linux`)
- `socket_options_bsd.go` (`//go:build freebsd || darwin || dragonfly || netbsd || openbsd`)
- `socket_options_other.go` (`//go:build !linux && !freebsd && !darwin && !dragonfly && !netbsd && !openbsd`) — no-op plus one-time warn log.

Common signature:

```go
type socketOptions struct {
    IPv4TTL      uint8  // 0 means "do not set"
    IPv6HopLimit uint8  // 0 means "do not set"
    DSCP         int    // negative means "do not set"
}

func applySocketOptions(network string, c syscall.RawConn, opts socketOptions) error
```

Linux/BSD body (sketch):

```go
var setErr error
ctrlErr := c.Control(func(fd uintptr) {
    if opts.IPv4TTL > 0 && (network == "tcp" || network == "tcp4") {
        // Cast uint8 -> int at the syscall boundary.
        if err := unix.SetsockoptInt(int(fd), unix.IPPROTO_IP, unix.IP_TTL, int(opts.IPv4TTL)); err != nil {
            setErr = fmt.Errorf("set IP_TTL=%d: %w", opts.IPv4TTL, err); return
        }
    }
    if opts.IPv6HopLimit > 0 && (network == "tcp" || network == "tcp6") {
        if err := unix.SetsockoptInt(int(fd), unix.IPPROTO_IPV6, unix.IPV6_UNICAST_HOPS, int(opts.IPv6HopLimit)); err != nil {
            setErr = fmt.Errorf("set IPV6_UNICAST_HOPS=%d: %w", opts.IPv6HopLimit, err); return
        }
    }
    if opts.DSCP >= 0 {
        tos := opts.DSCP << 2  // upper 6 bits DSCP; lower 2 bits ECN (kernel-managed)
        if network == "tcp" || network == "tcp4" {
            if err := unix.SetsockoptInt(int(fd), unix.IPPROTO_IP, unix.IP_TOS, tos); err != nil {
                setErr = fmt.Errorf("set IP_TOS for DSCP=%d: %w", opts.DSCP, err); return
            }
        }
        if network == "tcp" || network == "tcp6" {
            if err := unix.SetsockoptInt(int(fd), unix.IPPROTO_IPV6, unix.IPV6_TCLASS, tos); err != nil {
                setErr = fmt.Errorf("set IPV6_TCLASS for DSCP=%d: %w", opts.DSCP, err); return
            }
        }
    }
})
if ctrlErr != nil {
    return ctrlErr
}
return setErr
```

For dual-stack `[::]:port` listens (`network == "tcp"`), all relevant v4 and v6 options are set; the kernel applies the right ones per outbound packet.

`setsockopt` failures are surfaced — never swallowed — because silent fallback defeats both security (TTL) and correctness (DSCP marking) purposes.

### Definition of done — Step 2

- [ ] Three files compile under `GOOS=linux,freebsd,darwin,windows`.
- [ ] `applySocketOptions` signature stable across platforms.
- [ ] Linux path correctly calls all four socket options when appropriate.
- [ ] DSCP shift (`<< 2`) verified; ECN bits not touched.
- [ ] Non-Unix platforms log exactly one warn-level message when any option is configured.
- [ ] `setsockopt` errors propagate out of `Listen`.

## Step 3 — Wire into `ListenAndServe`

Three code paths to touch in `tls_config.go`:

**Regular TCP** (line 323): replace `net.Listen` with `net.ListenConfig.Listen` carrying our `Control` callback.

```go
v4ttl, _ := effective[uint8](flags.WebIPv4TTL, 0, cfg.IPSocketConfig.IPv4TTL)
v6hop, _ := effective[uint8](flags.WebIPv6HopLimit, 0, cfg.IPSocketConfig.IPv6HopLimit)
dscp, dscpSet := effective[int](flags.WebDSCP, -1, cfg.IPSocketConfig.DSCP)
opts := socketOptions{IPv4TTL: v4ttl, IPv6HopLimit: v6hop}
if dscpSet {
    opts.DSCP = dscp
} else {
    opts.DSCP = -1
}
lc := net.ListenConfig{
    Control: func(network, address string, c syscall.RawConn) error {
        return applySocketOptions(network, c, opts)
    },
}
listener, err = lc.Listen(context.Background(), "tcp", address)
```

(`cfg` comes from `getConfig(*flags.WebConfigFile)` which `ListenAndServe` already calls before binding; if no config file is provided, `cfg.IPSocketConfig` is the zero value and only the flag/env path is in play.)

**VSOCK** (lines 316–321): if any of the three options is configured, log at info level ("ignoring IP socket options on VSOCK listener %s") and proceed.

**Systemd socket activation** (lines 297–306): for each `*net.TCPListener` returned by `activation.Listeners()`, call `tcpLn.File()`, apply options via `unix.SetsockoptInt` on the dup'd FD, close the dup. Non-TCP systemd listeners are skipped with a debug log.

### Definition of done — Step 3

- [ ] Regular TCP path uses `net.ListenConfig.Control`.
- [ ] VSOCK path logs and skips, never errors when options are configured.
- [ ] Systemd path applies options post-bind via dup'd FD.
- [ ] TLS-wrapped path continues to function (verified by test, no code change needed).
- [ ] No regression in existing `ListenAndServe` tests.

## Step 4 — Tests

The toolkit's existing test style is light-to-moderate: table-driven YAML validation via `TestYAMLFiles` with `web/testdata/*.yml` files; real `net.Listen` + dial-in behavior tests; plain `t.Fatalf`/`t.Errorf`; no testify; no existing `getsockopt` testing; Linux-only CI. The plan matches that style — two additions, no new mocking infrastructure.

### 4a. Validation: extend `TestYAMLFiles`

Add 4 bad + 1 good testdata files to `web/testdata/`, wire them into `testTables` and `ErrorMap` in `tls_config_test.go`:

| File | Body | Expected error |
|---|---|---|
| `web_config_ipv4_ttl_zero.bad.yml` | `ip_socket_config: {ipv4_ttl: 0}` | `ipv4_ttl must be in range 1-255` |
| `web_config_ipv4_ttl_high.bad.yml` | `ip_socket_config: {ipv4_ttl: 256}` | YAML overflow or our range error |
| `web_config_dscp_neg.bad.yml` | `ip_socket_config: {dscp: -1}` | `dscp must be in range 0-63` |
| `web_config_dscp_high.bad.yml` | `ip_socket_config: {dscp: 64}` | `dscp must be in range 0-63` |
| `web_config_ip_socket.good.yml` | full valid config with TTL=2, hop_limit=2, dscp=46 | (no error) |

Zero new machinery — same pattern as the 30+ existing testdata files.

### 4b. Behavior: one new Linux-gated table-driven test

New file `web/socket_options_linux_test.go` (`//go:build linux`). Single test function with a table of ~6 subtests that each:

1. Build a `net.ListenConfig` with the same `Control` hook the feature installs.
2. `lc.Listen(...)` on a fresh port.
3. `getsockopt` on the listener FD (via `(*net.TCPListener).SyscallConn()`) — verify `IP_TTL`, `IPV6_UNICAST_HOPS`, `IP_TOS`, `IPV6_TCLASS` as appropriate (mask ECN before comparing DSCP).
4. Dial in from a goroutine; `Accept`.
5. `getsockopt` on the accepted conn FD (via `(*net.TCPConn).SyscallConn()`) — same expected values. This is the load-bearing inheritance claim.

Subtests (9 total — positive / boundary / corner explicitly covered):

| Subtest | Family | TTL | Hop | DSCP | Role |
|---|---|---|---|---|---|
| `ipv4_ttl_min` | tcp4 | 1 | — | — | boundary low + security extreme |
| `ipv4_ttl_mid` | tcp4 | 7 | — | — | positive |
| `ipv4_ttl_max` | tcp4 | 255 | — | — | boundary high |
| `ipv6_hop_mid` | tcp6 | — | 4 | — | positive (v6) |
| `dscp_zero` | tcp4 | — | — | 0 | corner — explicit 0 IS configured |
| `dscp_mid` | tcp4 | — | — | 46 | positive (EF) |
| `dscp_max` | tcp4 | — | — | 63 | boundary high |
| `all_options_v4` | tcp4 | 3 | — | 16 | combined |
| `dual_stack_all` | tcp `[::]:0` | 2 | 2 | 26 | corner — both v4 and v6 options on one socket |

~120 lines total. Uses only stdlib + `golang.org/x/sys/unix`. No fake `RawConn`, no recording hooks, no slog handler interception.

### 4d. Case-coverage matrix

| Category | Covered by |
|---|---|
| Positive | `ipv4_ttl_mid`, `ipv6_hop_mid`, `dscp_mid`, `all_options_v4`, `dual_stack_all`; good-YAML testdata. |
| Negative (rejected at load time) | 4 bad-YAML testdata files in §4a. |
| Boundary | `ipv4_ttl_min`, `ipv4_ttl_max`, `dscp_zero`, `dscp_max`. |
| Corner | `dscp_zero` (explicit 0 is configured, not skipped); `dual_stack_all` (both v4 and v6 options applied on `[::]:0`). |
| Attacker / malicious input | Out-of-range integers covered by negative testdata. `*uint8` flags can't accept negatives (parser-rejected). YAML type-confusion is yaml.v2's responsibility. Input space per knob is a single 8-bit integer — exhaustively covered by the boundary tests. No invented adversarial scenarios. |

### 4c. Tiny precedence test for `effective[T]`

A standalone ~20-line table test verifying flag-set wins over YAML, YAML wins over default, sentinel value means "not configured". No network. No build tag. Catches refactor regressions in the helper.

### Out of scope (justified omissions)

| Skipped | Why |
|---|---|
| TLS-wrapped listener | `tls.NewListener` is std-lib transparent; would test std-lib, not us. |
| VSOCK skip path | Requires vsock device. Manual smoke test only. |
| Systemd activation path | Requires systemd FDs. Manual smoke test only. |
| `setsockopt` error propagation | Needs a fake `syscall.RawConn` — no precedent in toolkit; mocking risk > value. |
| Cross-platform builds | CI is Linux-only; cross-compile is a `make`/manual check. |
| Flag/env precedence directly | Kingpin's `.Envar()` is exercised by every other toolkit flag; `effective[T]` test covers the in-package layer. |

### Definition of done — Step 4

- [ ] 5 new `web/testdata/web_config_*.yml` files wired into `testTables` and `ErrorMap`.
- [ ] `TestApplySocketOptions_Inheritance` in `web/socket_options_linux_test.go` (build-tagged), **9 passing subtests** covering positive / boundary / corner per the §4d matrix.
- [ ] Small `TestEffective` table test for `effective[T]` precedence.
- [ ] `go test ./web/...` clean on Linux CI.
- [ ] No new mocking infrastructure; no new test dependencies in `go.mod`.

## Appendix A — Optional follow-up commit: migrating `handler_test.go` to table-driven

This appendix proposes an **optional, clearly-separated commit** on the same `ttl` branch that converts `web/handler_test.go` to a table-driven structure. The commit is isolated from the feature commits so reviewers can either accept it, drop it via `git rebase -i`, or request it be split into its own PR — without that decision blocking the feature itself.

### Current state of table-driven density

| File | Lines | Table-driven? | Notes |
|---|---|---|---|
| `web/tls_config_test.go` | 714 | **Yes** — `TestYAMLFiles` + `TestInputs` slice drives the majority. | Already the model we plug new validation cases into. No conversion needed. |
| `web/handler_test.go` | 257 | **No** — 4 separate named test functions covering auth caching, basic-auth headers, rate limiting, etc. | The realistic conversion candidate. |
| `web/cache_test.go` | 37 | n/a — single short test. | Too small to bother. |
| `web/kingpinflag/` | 0 | n/a — no test file. | Could add a small table-driven `TestAddFlags` covering flag registration if there's appetite. |

### Why conversion of `handler_test.go` would help

- Adding new auth-related cases currently means writing a new top-level test function with its own setup/teardown duplication. Table form lets a new case be one row.
- The 4 existing tests share ~30 lines of nearly-identical fixture code (build `http.Server`, start goroutine, `waitForPort`, cleanup). A `TestInputs`-style fixture would consolidate that.
- The fixtures and assertions don't currently make it obvious which auth/cache scenarios are NOT tested; a table-driven format makes coverage gaps visible.

### Sketch of the refactor

```go
type handlerCase struct {
    name           string
    yamlConfig     string                                  // path under testdata/
    requests       []requestSpec                           // method, path, headers, body
    expectedStatus []int                                   // per-request
    cacheBehavior  func(t *testing.T, server *http.Server) // optional post-assert hook
}

func TestHandler(t *testing.T) {
    cases := []handlerCase{
        // BasicAuthCache, basic-auth header behavior, rate limiting, etc.
        // — each currently-separate test becomes one row.
    }
    for _, tc := range cases {
        t.Run(tc.name, func(t *testing.T) {
            // single shared fixture: ListenAndServe, waitForPort, t.Cleanup
            // walk tc.requests, assert against tc.expectedStatus
        })
    }
}
```

Estimated effort: ~1 day of refactor + careful diff-review to ensure no test behavior changed. Net line count likely shrinks 20–40%. No new behavior tested; no behavior tested less.

### Why this lives in a separate commit (not mixed into the feature commits)

- Reviewers expect feature commits to be feature-shaped. A sweeping test refactor mixed into the same commit as feature code obscures the actual change and slows review.
- The refactor is justified on maintainability, not on enabling the TTL/DSCP feature — those tests already exist as separate functions and our feature doesn't touch them.
- Keeping it as one self-contained commit makes it trivial for maintainers to drop or split: `git rebase -i upstream/master` and either `drop` the refactor commit or move it to its own branch for a follow-up PR.
- Bisect stays clean: if either the feature or the refactor introduces a regression, `git bisect` lands on the right commit.

### Commit organization on the `ttl` branch

The branch carries the work in this order so each commit is independently revertable:

1. `web: add IP socket-options config plumbing (FlagConfig, IPSocketConfig)` — Step 1.
2. `web: implement applySocketOptions for Linux/BSD/other` — Step 2.
3. `web: wire IP socket options into ListenAndServe` — Step 3.
4. `web: tests for IP socket options (validation + Linux inheritance)` — Step 4a + 4b + 4c.
5. `web: docs for ip_socket_config` — Step 5.
6. **`web: refactor handler_test.go to table-driven`** — this appendix. **Optional / droppable.**

A reviewer who wants only the feature can request "please drop commit 6" and the author rebases it out. A reviewer who likes the refactor can leave it. The branch description in the PR should call out commit 6 explicitly as optional and reference this appendix.

### Note on node_exporter

node_exporter's collector tests are file-fixture-based (procfs/sysfs trees under `collector/fixtures/`). Forcing them into table-driven form would fight the existing architecture rather than help it. We do **not** propose any conversion there.

## Step 5 — Documentation

- `docs/web-configuration.md`: new section "`ip_socket_config`" with annotated YAML example, security/QoS rationale, validation rules (TTL 1–255, DSCP 0–63), table of which listener flavors honor each option, note that ECN bits are not touched.
- `web/web-config.yml`: commented-out example block.
- `CHANGELOG.md`: one-line entry under the next unreleased version covering both TTL and DSCP.

### Definition of done — Step 5

- [ ] `docs/web-configuration.md` includes the new section with validation rules.
- [ ] `web/web-config.yml` ships with the commented example.
- [ ] `CHANGELOG.md` updated.

## Step 6 — Platform support and edge cases

| Platform | Status |
|---|---|
| Linux | CI-tested; load-bearing target. |
| FreeBSD, DragonFly, NetBSD, OpenBSD, Darwin | Build-supported, not CI-tested. |
| Windows | No-op + single warn log. Note: Windows IP_TOS is subject to the QoS API; even outside this exporter, raw setsockopt may be ignored without a registry tweak. |
| Other (Plan 9, JS/Wasm, …) | No-op + single warn log. |

| Edge case | Handling |
|---|---|
| TLS-wrapped listener | Transparent — `tls.NewListener` passes through. |
| HTTP/2 | Same TCP transport; no impact. |
| Dual-stack `[::]:port` | All relevant v4 and v6 options set. |
| VSOCK | No IP layer; log-and-skip. |
| Systemd socket activation | Apply post-bind via dup'd FD. |
| ECN bits | Never touched; `dscp << 2` only writes upper 6 bits. |
| `IPV6_V6ONLY` | Not modified. |
| Explicit `ipv4_ttl: 0` in YAML | Rejected at config-load time. |
| Explicit `dscp: 0` in YAML | Accepted; `setsockopt(IP_TOS, 0)` called. |

### Definition of done — Step 6

- [ ] Cross-compile matrix succeeds for `GOOS=linux,freebsd,darwin,windows`.
- [ ] Windows path emits exactly one warning at startup.
- [ ] VSOCK + any-option-configured starts cleanly.
- [ ] Systemd path manually verified with a unit file using `ListenStream=`.
- [ ] DSCP wire value verified via `tcpdump` (upper 6 bits of ToS match configured DSCP).

## Summary

This brief proposes adding `--web.ipv4-ttl`, `--web.ipv6-hop-limit`, and `--web.dscp` flags (with env-var and YAML equivalents) to `web.ListenAndServe`. The implementation hooks `net.ListenConfig.Control` to call `setsockopt` on `IP_TTL`, `IPV6_UNICAST_HOPS`, `IP_TOS` (DSCP shifted into the upper 6 bits), and `IPV6_TCLASS` pre-bind. On Linux these options are inherited by accepted connections, so the SYN-ACK and all subsequent response packets carry the configured values. VSOCK ignores all three; systemd socket-activated listeners get them applied post-bind via a dup'd FD. TTL and Hop Limit accept 1–255 (with 0 reserved as the not-configured sentinel — RFC 1122 forbids hosts from sending TTL=0). DSCP accepts 0–63 (with -1 as the sentinel since 0 = CS0 is a valid configured value); ECN bits are left for the kernel to manage. Linux is the load-bearing platform; BSD/Darwin compile; Windows is a no-op with a warning.
