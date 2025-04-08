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
	webExternalURL := a.Flag(
		"web.external-url",
		"The URL under which the exporter is externally reachable (for example, if served via a reverse proxy). Used for generating relative and absolute links back to the exporter itself. If the URL has a path portion, it will be used to prefix all HTTP endpoints served by the exporter. If omitted, relevant URL components will be derived automatically.",
	).PlaceHolder("<url>").String()
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
		WebExternalURL: webExternalURL,
		WebRoutePrefix: a.Flag("web.route-prefix", "Prefix for the internal routes of web endpoints. Defaults to path of --web.external-url.").Default(*webExternalURL).String(),
		WebMetricsPath: a.Flag("web.telemetry-path", "Path under which to expose metrics.").Default("/metrics").String(),
	}
	return &flags
}
