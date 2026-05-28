// Copyright 2020 The Prometheus Authors
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
package kingpinflag

import (
	"runtime"

	"github.com/alecthomas/kingpin/v2"
	"github.com/prometheus/exporter-toolkit/web"
)

type flagGroup interface {
	Flag(string, string) *kingpin.FlagClause
}

var _ flagGroup = &kingpin.Application{}

// AddFlags adds the flags used by this package to the Kingpin application or CmdClause.
// To use the default Kingpin application, call
// AddFlags(kingpin.CommandLine, ":portNum") where portNum is the default port.
func AddFlags(a flagGroup, defaultAddress string) *web.FlagConfig {
	systemdSocket := func() *bool { b := false; return &b }() // Socket activation only available on Linux
	if runtime.GOOS == "linux" {
		systemdSocket = a.Flag(
			"web.systemd-socket",
			"Use systemd socket activation listeners instead of port listeners (Linux only).",
		).Bool()
	}
	flags := web.FlagConfig{
		WebListenAddresses: a.Flag(
			"web.listen-address",
			"Addresses on which to expose metrics and web interface. Repeatable for multiple addresses. Examples: `:9100` or `[::1]:9100` for http, `vsock://:9100` for vsock",
		).Default(defaultAddress).HintOptions(defaultAddress).Strings(),
		WebSystemdSocket: systemdSocket,
		WebConfigFile: a.Flag(
			"web.config.file",
			"Path to configuration file that can enable TLS or authentication. See: https://github.com/prometheus/exporter-toolkit/blob/master/docs/web-configuration.md",
		).Default("").String(),
		WebIPv4TTL: a.Flag(
			"web.ipv4-ttl",
			"IPv4 TTL to set on the listening socket. Valid: 1-255. 0 (default) leaves the kernel default. Lower values bound how far response packets can travel.",
		).Default("0").Envar("WEB_IPV4_TTL").Uint8(),
		WebIPv6HopLimit: a.Flag(
			"web.ipv6-hop-limit",
			"IPv6 Hop Limit to set on the listening socket. Valid: 1-255. 0 (default) leaves the kernel default.",
		).Default("0").Envar("WEB_IPV6_HOP_LIMIT").Uint8(),
		WebDSCP: a.Flag(
			"web.dscp",
			"DSCP codepoint applied to outbound packets via IPv4 ToS and IPv6 Traffic Class (upper 6 bits). Valid: 0-63. -1 (default) leaves the kernel default. ECN bits are left for the kernel.",
		).Default("-1").Envar("WEB_DSCP").Int(),
	}
	return &flags
}
