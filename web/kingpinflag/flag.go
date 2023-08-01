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

// AddFlags adds the flags used by this package to the Kingpin application.
// To use the default Kingpin application, call
// AddFlags(kingpin.CommandLine, ":portNum") where portNum is the default port.
func AddFlags(a *kingpin.Application, defaultAddress string) *web.FlagConfig {
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
			"Addresses on which to expose metrics and web interface. Repeatable for multiple addresses.",
		).Default(defaultAddress).Strings(),
		WebSystemdSocket: systemdSocket,
		WebConfigFile: a.Flag(
			"web.config.file",
			"Path to configuration file that can enable TLS or authentication. See: https://github.com/prometheus/exporter-toolkit/blob/master/docs/web-configuration.md",
		).Default("").String(),
	}
	return &flags
}
