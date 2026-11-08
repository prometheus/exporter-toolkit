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

package web

import (
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"path"
	"strings"
)

// ErrProbeConfigMissing is returned when a probe listen address is set without probe path configuration.
var ErrProbeConfigMissing = errors.New("probe listen address is set but probe configuration is missing")

// ErrProbeAddressInUse is returned when the probe listen address matches a main web listen address.
var ErrProbeAddressInUse = errors.New("probe listen address conflicts with a main web listen address")

// ErrProbeVsockUnsupported is returned when a vsock address is used for the probe listener.
var ErrProbeVsockUnsupported = errors.New("vsock addresses are not supported for the probe listener")

// ErrProbePathInvalid is returned when an allowed probe path is not a rooted URL path.
var ErrProbePathInvalid = errors.New("probe allowed path must be a rooted URL path")

// ProbeConfig configures the optional plain-HTTP probe listener. Binaries set this on FlagConfig
// before ListenAndServe or ServeMultipleWithProbe; only the listen address comes from the command line.
type ProbeConfig struct {
	// AllowedPaths are exact rooted URL paths, such as "/-/healthy".
	AllowedPaths []string
	Handler      http.Handler
}

func (c *FlagConfig) probeListenAddress() string {
	if c == nil || c.WebProbeListenAddress == nil {
		return ""
	}
	return strings.TrimSpace(*c.WebProbeListenAddress)
}

func (c *FlagConfig) validateProbeConfig() error {
	addr := c.probeListenAddress()
	if addr == "" {
		return nil
	}
	if strings.HasPrefix(addr, "vsock://") {
		return ErrProbeVsockUnsupported
	}
	if c.WebSystemdSocket == nil || !*c.WebSystemdSocket {
		if c.WebListenAddresses != nil {
			for _, mainAddr := range *c.WebListenAddresses {
				if probeConflictsWithMain(addr, mainAddr) {
					return fmt.Errorf("%w: %s", ErrProbeAddressInUse, addr)
				}
			}
		}
	}
	if c.Probe == nil || c.Probe.Handler == nil || len(c.Probe.AllowedPaths) == 0 {
		return ErrProbeConfigMissing
	}
	for _, p := range c.Probe.AllowedPaths {
		cleaned := path.Clean(p)
		if cleaned != p || !strings.HasPrefix(cleaned, "/") {
			return fmt.Errorf("%w: %q", ErrProbePathInvalid, p)
		}
	}
	return nil
}

func probeConflictsWithMain(probe, main string) bool {
	if probe == main {
		return true
	}
	probeHost, probePort, err1 := splitListenHostPort(probe)
	mainHost, mainPort, err2 := splitListenHostPort(main)
	if err1 != nil || err2 != nil {
		return false
	}
	if probePort != mainPort {
		return false
	}
	if hostListensAllInterfaces(probeHost) || hostListensAllInterfaces(mainHost) {
		return true
	}
	return probeHost == mainHost
}

func splitListenHostPort(address string) (host, port string, err error) {
	return net.SplitHostPort(address)
}

func hostListensAllInterfaces(host string) bool {
	if host == "" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsUnspecified()
}

type probeHandler struct {
	allowed map[string]struct{}
	handler http.Handler
}

func newProbeHandler(cfg *ProbeConfig) http.Handler {
	allowed := make(map[string]struct{}, len(cfg.AllowedPaths))
	for _, p := range cfg.AllowedPaths {
		allowed[path.Clean(p)] = struct{}{}
	}
	return &probeHandler{
		allowed: allowed,
		handler: cfg.Handler,
	}
}

func (h *probeHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if strings.Contains(r.URL.Path, "..") {
		http.NotFound(w, r)
		return
	}
	cleaned := path.Clean(r.URL.Path)
	if _, ok := h.allowed[cleaned]; !ok {
		http.NotFound(w, r)
		return
	}
	h.handler.ServeHTTP(w, r)
}

func newProbeServer(main *http.Server, cfg *ProbeConfig) *http.Server {
	probe := &http.Server{
		Handler: newProbeHandler(cfg),
	}
	if main != nil {
		probe.ReadHeaderTimeout = main.ReadHeaderTimeout
		probe.ReadTimeout = main.ReadTimeout
		probe.WriteTimeout = main.WriteTimeout
		probe.IdleTimeout = main.IdleTimeout
		probe.MaxHeaderBytes = main.MaxHeaderBytes
	}
	return probe
}

func serveProbeListener(l net.Listener, server *http.Server, allowedPaths []string, logger *slog.Logger) error {
	logger.Info(
		"Probe listener is enabled.",
		"address", l.Addr().String(),
		"tls", false,
		"basic_auth", false,
		"allowed_paths", allowedPaths,
	)
	return server.Serve(l)
}
