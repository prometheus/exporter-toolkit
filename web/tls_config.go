// Copyright 2019 The Prometheus Authors
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
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/coreos/go-systemd/v22/activation"
	"github.com/mdlayher/vsock"
	config_util "github.com/prometheus/common/config"
	"go.yaml.in/yaml/v2"
	"golang.org/x/sync/errgroup"
	"golang.org/x/time/rate"
)

var (
	errNoTLSConfig = errors.New("TLS config is not present")
	ErrMissingFlag = errors.New("missing required flag configuration")
	ErrNoListeners = errors.New("no web listen address or systemd socket flag specified")
)

type Config struct {
	TLSConfig         TLSConfig                     `yaml:"tls_server_config"`
	HTTPConfig        HTTPConfig                    `yaml:"http_server_config"`
	RateLimiterConfig RateLimiterConfig             `yaml:"rate_limit"`
	Users             map[string]config_util.Secret `yaml:"basic_auth_users"`
	IPSocketConfig    IPSocketConfig                `yaml:"ip_socket_config"`
}

type TLSConfig struct {
	TLSCert                  string             `yaml:"cert"`
	TLSKey                   config_util.Secret `yaml:"key"`
	ClientCAsText            string             `yaml:"client_ca"`
	TLSCertPath              string             `yaml:"cert_file"`
	TLSKeyPath               string             `yaml:"key_file"`
	ClientAuth               string             `yaml:"client_auth_type"`
	ClientCAs                string             `yaml:"client_ca_file"`
	CipherSuites             []Cipher           `yaml:"cipher_suites"`
	CurvePreferences         []Curve            `yaml:"curve_preferences"`
	MinVersion               TLSVersion         `yaml:"min_version"`
	MaxVersion               TLSVersion         `yaml:"max_version"`
	PreferServerCipherSuites bool               `yaml:"prefer_server_cipher_suites"`
	ClientAllowedSans        []string           `yaml:"client_allowed_sans"`
}

type FlagConfig struct {
	// WebListenAddresses contains the listen addresses for the HTTP server.
	WebListenAddresses *[]string
	// WebSystemdSocket enables systemd socket activation listeners.
	WebSystemdSocket *bool
	// WebConfigFile points to the TLS and authentication configuration file.
	WebConfigFile *string
	// WebIPv4TTL is the IPv4 TTL to set on the listening socket.
	// Sentinel 0 (or nil) means "not configured; use kernel default".
	WebIPv4TTL *uint8
	// WebIPv6HopLimit is the IPv6 Hop Limit to set on the listening socket.
	// Sentinel 0 (or nil) means "not configured; use kernel default".
	WebIPv6HopLimit *uint8
	// WebDSCP is the DSCP codepoint (upper 6 bits of IP ToS / IPv6 Traffic Class).
	// Sentinel -1 (or nil) means "not configured". Valid configured range: 0-63.
	WebDSCP *int
}

// checkFlags validates that the flag configuration contains the required
// listener and web config fields needed by the web package.
func (c *FlagConfig) checkFlags() error {
	if c == nil {
		return ErrMissingFlag
	}
	if c.WebConfigFile == nil {
		return ErrMissingFlag
	}
	if c.WebSystemdSocket == nil && (c.WebListenAddresses == nil || len(*c.WebListenAddresses) == 0) {
		return ErrNoListeners
	}
	return nil
}

// SetDirectory joins any relative file paths with dir.
func (t *TLSConfig) SetDirectory(dir string) {
	t.TLSCertPath = config_util.JoinDir(dir, t.TLSCertPath)
	t.TLSKeyPath = config_util.JoinDir(dir, t.TLSKeyPath)
	t.ClientCAs = config_util.JoinDir(dir, t.ClientCAs)
}

// VerifyPeerCertificate will check the SAN entries of the client cert if there is configuration for it
func (t *TLSConfig) VerifyPeerCertificate(rawCerts [][]byte, _ [][]*x509.Certificate) error {
	// sender cert comes first, see https://www.rfc-editor.org/rfc/rfc5246#section-7.4.2
	cert, err := x509.ParseCertificate(rawCerts[0])
	if err != nil {
		return fmt.Errorf("error parsing client certificate: %s", err)
	}

	// Build up a slice of strings with all Subject Alternate Name values
	sanValues := append(cert.DNSNames, cert.EmailAddresses...)

	for _, ip := range cert.IPAddresses {
		sanValues = append(sanValues, ip.String())
	}

	for _, uri := range cert.URIs {
		sanValues = append(sanValues, uri.String())
	}

	for _, sanValue := range sanValues {
		if slices.Contains(t.ClientAllowedSans, sanValue) {
			return nil
		}
	}

	return fmt.Errorf("could not find allowed SANs in client cert, found: %v", t.ClientAllowedSans)
}

type HTTPConfig struct {
	HTTP2  bool              `yaml:"http2"`
	Header map[string]string `yaml:"headers,omitempty"`
}

type RateLimiterConfig struct {
	Burst    int           `yaml:"burst"`
	Interval time.Duration `yaml:"interval"`
}

// IPSocketConfig configures IP-layer socket options applied to the listening
// socket. All fields are optional; an omitted (nil) field means "not configured;
// use the kernel default".
//
// Valid ranges:
//   - IPv4TTL, IPv6HopLimit: 1-255. (TTL=0 is forbidden by RFC 1122 and not
//     useful since the first router decrements it to -1 and discards.)
//   - DSCP: 0-63. The 6-bit DSCP codepoint is shifted into the upper 6 bits of
//     the IPv4 ToS / IPv6 Traffic Class byte; the lower 2 bits (ECN) are left
//     for the kernel to manage on ECN-capable TCP connections.
//
// On Linux, options set on the listening socket are inherited by accepted
// connections including the SYN-ACK packet. See accept(2), ip(7), ipv6(7).
type IPSocketConfig struct {
	IPv4TTL      *uint8 `yaml:"ipv4_ttl"`
	IPv6HopLimit *uint8 `yaml:"ipv6_hop_limit"`
	DSCP         *int   `yaml:"dscp"`
}

// socketOptions is the resolved set of IP socket options to apply to a
// listening socket. Sentinels: IPv4TTL/IPv6HopLimit == 0 means "do not set",
// DSCP < 0 means "do not set".
type socketOptions struct {
	IPv4TTL      uint8
	IPv6HopLimit uint8
	DSCP         int
}

// anySet reports whether any option is configured.
func (o socketOptions) anySet() bool {
	return o.IPv4TTL > 0 || o.IPv6HopLimit > 0 || o.DSCP >= 0
}

func getConfig(configPath string) (*Config, error) {
	content, err := os.ReadFile(configPath)
	if err != nil {
		return nil, err
	}
	c := &Config{
		TLSConfig: TLSConfig{
			MinVersion:               tls.VersionTLS12,
			MaxVersion:               tls.VersionTLS13,
			PreferServerCipherSuites: true,
		},
		HTTPConfig: HTTPConfig{HTTP2: true},
	}
	err = yaml.UnmarshalStrict(content, c)
	if err == nil {
		err = validateHeaderConfig(c.HTTPConfig.Header)
	}
	if err == nil {
		err = validateIPSocketConfig(c.IPSocketConfig)
	}
	c.TLSConfig.SetDirectory(filepath.Dir(configPath))
	return c, err
}

// validateIPSocketConfig enforces value-range rules. The uint8 type on the TTL
// fields already excludes negatives and values >255 at YAML-parse time, so we
// only need to reject the explicit-zero sentinel here.
func validateIPSocketConfig(c IPSocketConfig) error {
	if c.IPv4TTL != nil && *c.IPv4TTL < 1 {
		return fmt.Errorf("ipv4_ttl must be in range 1-255, got %d", *c.IPv4TTL)
	}
	if c.IPv6HopLimit != nil && *c.IPv6HopLimit < 1 {
		return fmt.Errorf("ipv6_hop_limit must be in range 1-255, got %d", *c.IPv6HopLimit)
	}
	if c.DSCP != nil && (*c.DSCP < 0 || *c.DSCP > 63) {
		return fmt.Errorf("dscp must be in range 0-63, got %d", *c.DSCP)
	}
	return nil
}

// effective resolves the configured value for an IP socket option applying
// flag > YAML > default precedence. flagVal is the parsed pointer from kingpin
// (non-nil after parse; equal to flagSentinel when the operator did not set
// the flag). yamlVal is the YAML field pointer, nil when the field is absent.
// Returns the resolved value and true if the option was configured, otherwise
// the zero value and false.
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

// resolveSocketOptions builds a socketOptions value from the flag and YAML
// configuration, applying the documented precedence (flag > env > YAML >
// default). The YAML config is loaded from flags.WebConfigFile if set.
func resolveSocketOptions(flags *FlagConfig) (socketOptions, error) {
	var yamlV4, yamlV6 *uint8
	var yamlDSCP *int
	if flags.WebConfigFile != nil && *flags.WebConfigFile != "" {
		cfg, err := getConfig(*flags.WebConfigFile)
		if err != nil {
			return socketOptions{}, err
		}
		yamlV4 = cfg.IPSocketConfig.IPv4TTL
		yamlV6 = cfg.IPSocketConfig.IPv6HopLimit
		yamlDSCP = cfg.IPSocketConfig.DSCP
	}
	v4ttl, _ := effective(flags.WebIPv4TTL, uint8(0), yamlV4)
	v6hop, _ := effective(flags.WebIPv6HopLimit, uint8(0), yamlV6)
	dscp, dscpSet := effective(flags.WebDSCP, -1, yamlDSCP)
	// Flag-level range check for DSCP. The kingpin.Int() parser accepts any
	// int so a value like --web.dscp=999 would otherwise flow into setsockopt
	// where the kernel takes the low byte of (dscp << 2), silently producing
	// a DSCP value different from what the operator asked for.
	// (TTL/Hop-Limit don't need this guard: kingpin.Uint8() already rejects
	// negative and >255 values at parse time, and the 0 sentinel means
	// "not configured".)
	if dscpSet && (dscp < 0 || dscp > 63) {
		return socketOptions{}, fmt.Errorf("dscp must be in range 0-63, got %d", dscp)
	}
	opts := socketOptions{IPv4TTL: v4ttl, IPv6HopLimit: v6hop, DSCP: -1}
	if dscpSet {
		opts.DSCP = dscp
	}
	return opts, nil
}

func getTLSConfig(configPath string) (*tls.Config, error) {
	c, err := getConfig(configPath)
	if err != nil {
		return nil, err
	}
	return ConfigToTLSConfig(&c.TLSConfig)
}

func validateTLSPaths(c *TLSConfig) error {
	if c.TLSCertPath == "" && c.TLSCert == "" &&
		c.TLSKeyPath == "" && c.TLSKey == "" &&
		c.ClientCAs == "" && c.ClientCAsText == "" &&
		c.ClientAuth == "" {
		return errNoTLSConfig
	}

	if c.TLSCertPath == "" && c.TLSCert == "" {
		return errors.New("missing one of cert or cert_file")
	}

	if c.TLSKeyPath == "" && c.TLSKey == "" {
		return errors.New("missing one of key or key_file")
	}

	return nil
}

// ConfigToTLSConfig generates the golang tls.Config from the TLSConfig struct.
func ConfigToTLSConfig(c *TLSConfig) (*tls.Config, error) {
	if err := validateTLSPaths(c); err != nil {
		return nil, err
	}

	loadCert := func() (*tls.Certificate, error) {
		var certData, keyData []byte
		var err error

		if c.TLSCertPath != "" {
			certData, err = os.ReadFile(c.TLSCertPath)
			if err != nil {
				return nil, fmt.Errorf("failed to read cert_file (%s): %s", c.TLSCertPath, err)
			}
		} else {
			certData = []byte(c.TLSCert)
		}

		if c.TLSKeyPath != "" {
			keyData, err = os.ReadFile(c.TLSKeyPath)
			if err != nil {
				return nil, fmt.Errorf("failed to read key_file (%s): %s", c.TLSKeyPath, err)
			}
		} else {
			keyData = []byte(c.TLSKey)
		}

		cert, err := tls.X509KeyPair(certData, keyData)
		if err != nil {
			return nil, fmt.Errorf("failed to load X509KeyPair: %w", err)
		}
		return &cert, nil
	}

	// Confirm that certificate and key paths are valid.
	if _, err := loadCert(); err != nil {
		return nil, err
	}

	cfg := &tls.Config{
		MinVersion:               (uint16)(c.MinVersion),
		MaxVersion:               (uint16)(c.MaxVersion),
		PreferServerCipherSuites: c.PreferServerCipherSuites,
	}

	cfg.GetCertificate = func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
		return loadCert()
	}

	var cf []uint16
	for _, c := range c.CipherSuites {
		cf = append(cf, (uint16)(c))
	}
	if len(cf) > 0 {
		cfg.CipherSuites = cf
	}

	var cp []tls.CurveID
	for _, c := range c.CurvePreferences {
		cp = append(cp, (tls.CurveID)(c))
	}
	if len(cp) > 0 {
		cfg.CurvePreferences = cp
	}

	if c.ClientCAs != "" {
		clientCAPool := x509.NewCertPool()
		clientCAFile, err := os.ReadFile(c.ClientCAs)
		if err != nil {
			return nil, err
		}
		clientCAPool.AppendCertsFromPEM(clientCAFile)
		cfg.ClientCAs = clientCAPool
	} else if c.ClientCAsText != "" {
		clientCAPool := x509.NewCertPool()
		clientCAPool.AppendCertsFromPEM([]byte(c.ClientCAsText))
		cfg.ClientCAs = clientCAPool
	}

	if c.ClientAllowedSans != nil {
		// verify that the client cert contains an allowed SAN
		cfg.VerifyPeerCertificate = c.VerifyPeerCertificate
	}

	switch c.ClientAuth {
	case "RequestClientCert":
		cfg.ClientAuth = tls.RequestClientCert
	case "RequireAnyClientCert", "RequireClientCert": // Preserved for backwards compatibility.
		cfg.ClientAuth = tls.RequireAnyClientCert
	case "VerifyClientCertIfGiven":
		cfg.ClientAuth = tls.VerifyClientCertIfGiven
	case "RequireAndVerifyClientCert":
		cfg.ClientAuth = tls.RequireAndVerifyClientCert
	case "", "NoClientCert":
		cfg.ClientAuth = tls.NoClientCert
	default:
		return nil, errors.New("invalid ClientAuth: " + c.ClientAuth)
	}

	if (c.ClientCAs != "" || c.ClientCAsText != "") && cfg.ClientAuth == tls.NoClientCert {
		return nil, errors.New("client CA's have been configured without a Client Auth Policy")
	}

	return cfg, nil
}

// ServeMultiple starts the server on the given listeners. The FlagConfig is
// also passed on to Serve.
func ServeMultiple(listeners []net.Listener, server *http.Server, flags *FlagConfig, logger *slog.Logger) error {
	errs := new(errgroup.Group)
	for _, l := range listeners {
		errs.Go(func() error {
			return Serve(l, server, flags, logger)
		})
	}
	return errs.Wait()
}

// ListenAndServe starts the server on addresses given in WebListenAddresses in
// the FlagConfig. When address starts looks like vsock://:{port}, it listens on
// vsock. More info check https://wiki.qemu.org/Features/VirtioVsock .
// Or instead uses systemd socket activated listeners if WebSystemdSocket in the
// FlagConfig is true.
// The FlagConfig is also passed on to ServeMultiple.
func ListenAndServe(server *http.Server, flags *FlagConfig, logger *slog.Logger) error {
	if err := flags.checkFlags(); err != nil {
		return err
	}

	// Resolve IP socket options from flags + YAML config (precedence: flag > env > YAML).
	// This is loaded once here and reused across all listener paths.
	opts, err := resolveSocketOptions(flags)
	if err != nil {
		return err
	}

	if flags.WebSystemdSocket != nil && *flags.WebSystemdSocket {
		logger.Info("Listening on systemd activated listeners instead of port listeners.")
		listeners, err := activation.Listeners()
		if err != nil {
			return err
		}
		if len(listeners) < 1 {
			return errors.New("no socket activation file descriptors found")
		}
		// Apply TTL/HopLimit (inherited options) post-bind to each TCP listener
		// handed to us by systemd; ListenConfig.Control isn't an option here
		// because the sockets are already bound. Then wrap each listener so
		// DSCP (not inherited) is applied per accepted connection.
		for i, ln := range listeners {
			tcpLn, ok := ln.(*net.TCPListener)
			if !ok {
				continue
			}
			if opts.IPv4TTL > 0 || opts.IPv6HopLimit > 0 {
				rc, err := tcpLn.SyscallConn()
				if err != nil {
					return fmt.Errorf("get syscall conn for systemd listener: %w", err)
				}
				if err := applyListenerOptions(rc, opts); err != nil {
					return fmt.Errorf("apply IP socket options to systemd listener %s: %w", ln.Addr(), err)
				}
			}
			if opts.DSCP >= 0 {
				listeners[i] = &ipSocketListener{Listener: ln, opts: opts, logger: logger}
			}
		}
		return ServeMultiple(listeners, server, flags, logger)
	}

	listeners := make([]net.Listener, 0, len(*flags.WebListenAddresses))
	for _, address := range *flags.WebListenAddresses {
		var listener net.Listener
		if strings.HasPrefix(address, "vsock://") {
			if opts.anySet() {
				logger.Info("Ignoring IP socket options on VSOCK listener (VSOCK has no IP layer)", "address", address)
			}
			port, err := parseVsockPort(address)
			if err != nil {
				return err
			}
			listener, err = vsock.Listen(port, nil)
			if err != nil {
				return err
			}
		} else {
			lc := net.ListenConfig{
				Control: func(_, _ string, c syscall.RawConn) error {
					return applyListenerOptions(c, opts)
				},
			}
			var err error
			listener, err = lc.Listen(context.Background(), "tcp", address)
			if err != nil {
				return err
			}
			if opts.DSCP >= 0 {
				listener = &ipSocketListener{Listener: listener, opts: opts, logger: logger}
			}
		}
		defer listener.Close()
		listeners = append(listeners, listener)
	}
	return ServeMultiple(listeners, server, flags, logger)
}

// ipSocketListener wraps a net.Listener and applies per-connection IP socket
// options (currently DSCP via IP_TOS / IPV6_TCLASS) to each accepted
// connection. The options that ARE inherited from the listening socket --
// IP_TTL and IPV6_UNICAST_HOPS -- are set elsewhere via applyListenerOptions
// and need not be re-set per connection.
//
// A setsockopt failure on an accepted connection is logged but does not
// reject the connection: a working scrape over a non-fatal socket-option
// glitch is preferred to a hard listener failure.
type ipSocketListener struct {
	net.Listener
	opts   socketOptions
	logger *slog.Logger
}

func (l *ipSocketListener) Accept() (net.Conn, error) {
	conn, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	tcpConn, ok := conn.(*net.TCPConn)
	if !ok {
		return conn, nil
	}
	rc, rcErr := tcpConn.SyscallConn()
	if rcErr != nil {
		l.logger.Warn("could not get SyscallConn for accepted connection; DSCP not applied", "err", rcErr)
		return conn, nil
	}
	if err := applyConnOptions(rc, l.opts); err != nil {
		l.logger.Warn("could not apply DSCP to accepted connection", "remote", conn.RemoteAddr(), "err", err)
	}
	return conn, nil
}

func parseVsockPort(address string) (uint32, error) {
	uri, err := url.Parse(address)
	if err != nil {
		return 0, err
	}
	_, portStr, err := net.SplitHostPort(uri.Host)
	if err != nil {
		return 0, err
	}
	port, err := strconv.ParseUint(portStr, 10, 32)
	if err != nil {
		return 0, err
	}
	return uint32(port), nil
}

// Server starts the server on the given listener. Based on the file path
// WebConfigFile in the FlagConfig, TLS or basic auth could be enabled.
func Serve(l net.Listener, server *http.Server, flags *FlagConfig, logger *slog.Logger) error {
	logger.Info("Listening on", "address", l.Addr().String())
	tlsConfigPath := *flags.WebConfigFile
	if tlsConfigPath == "" {
		logger.Info("TLS is disabled.", "http2", false, "address", l.Addr().String())
		return server.Serve(l)
	}

	if err := validateUsers(tlsConfigPath); err != nil {
		return err
	}

	// Setup basic authentication.
	var handler http.Handler = http.DefaultServeMux
	if server.Handler != nil {
		handler = server.Handler
	}

	c, err := getConfig(tlsConfigPath)
	if err != nil {
		return err
	}

	var limiter *rate.Limiter
	if c.RateLimiterConfig.Interval != 0 {
		limiter = rate.NewLimiter(rate.Every(c.RateLimiterConfig.Interval), c.RateLimiterConfig.Burst)
		logger.Info("Rate Limiter is enabled.", "burst", c.RateLimiterConfig.Burst, "interval", c.RateLimiterConfig.Interval)
	}

	server.Handler = &webHandler{
		tlsConfigPath: tlsConfigPath,
		logger:        logger,
		handler:       handler,
		cache:         newCache(),
		limiter:       limiter,
	}

	config, err := ConfigToTLSConfig(&c.TLSConfig)
	switch err {
	case nil:
		if !c.HTTPConfig.HTTP2 {
			server.TLSNextProto = make(map[string]func(*http.Server, *tls.Conn, http.Handler))
		}
		// Valid TLS config.
		logger.Info("TLS is enabled.", "http2", c.HTTPConfig.HTTP2, "address", l.Addr().String())
	case errNoTLSConfig:
		// No TLS config, back to plain HTTP.
		logger.Info("TLS is disabled.", "http2", false, "address", l.Addr().String())
		return server.Serve(l)
	default:
		// Invalid TLS config.
		return err
	}

	server.TLSConfig = config

	// Set the GetConfigForClient method of the HTTPS server so that the config
	// and certs are reloaded on new connections.
	server.TLSConfig.GetConfigForClient = func(*tls.ClientHelloInfo) (*tls.Config, error) {
		config, err := getTLSConfig(tlsConfigPath)
		if err != nil {
			return nil, err
		}
		config.NextProtos = server.TLSConfig.NextProtos
		return config, nil
	}
	return server.ServeTLS(l, "", "")
}

// Validate configuration file by reading the configuration and the certificates.
func Validate(tlsConfigPath string) error {
	if tlsConfigPath == "" {
		return nil
	}
	if err := validateUsers(tlsConfigPath); err != nil {
		return err
	}
	c, err := getConfig(tlsConfigPath)
	if err != nil {
		return err
	}
	_, err = ConfigToTLSConfig(&c.TLSConfig)
	if err == errNoTLSConfig {
		return nil
	}
	return err
}

type Cipher uint16

func (c *Cipher) UnmarshalYAML(unmarshal func(any) error) error {
	var s string
	err := unmarshal(&s)
	if err != nil {
		return err
	}
	for _, cs := range tls.CipherSuites() {
		if cs.Name == s {
			*c = (Cipher)(cs.ID)
			return nil
		}
	}
	return errors.New("unknown cipher: " + s)
}

func (c Cipher) MarshalYAML() (any, error) {
	return tls.CipherSuiteName((uint16)(c)), nil
}

type Curve tls.CurveID

var curves = map[string]Curve{
	"CurveP256": (Curve)(tls.CurveP256),
	"CurveP384": (Curve)(tls.CurveP384),
	"CurveP521": (Curve)(tls.CurveP521),
	"X25519":    (Curve)(tls.X25519),
}

func (c *Curve) UnmarshalYAML(unmarshal func(any) error) error {
	var s string
	err := unmarshal(&s)
	if err != nil {
		return err
	}
	if curveid, ok := curves[s]; ok {
		*c = curveid
		return nil
	}
	return errors.New("unknown curve: " + s)
}

func (c *Curve) MarshalYAML() (any, error) {
	for s, curveid := range curves {
		if *c == curveid {
			return s, nil
		}
	}
	return fmt.Sprintf("%v", c), nil
}

type TLSVersion uint16

var tlsVersions = map[string]TLSVersion{
	"TLS13": (TLSVersion)(tls.VersionTLS13),
	"TLS12": (TLSVersion)(tls.VersionTLS12),
	"TLS11": (TLSVersion)(tls.VersionTLS11),
	"TLS10": (TLSVersion)(tls.VersionTLS10),
}

func (tv *TLSVersion) UnmarshalYAML(unmarshal func(any) error) error {
	var s string
	err := unmarshal(&s)
	if err != nil {
		return err
	}
	if v, ok := tlsVersions[s]; ok {
		*tv = v
		return nil
	}
	return errors.New("unknown TLS version: " + s)
}

func (tv *TLSVersion) MarshalYAML() (any, error) {
	for s, v := range tlsVersions {
		if *tv == v {
			return s, nil
		}
	}
	return fmt.Sprintf("%v", tv), nil
}

// Listen starts the server on the given address. Based on the file
// tlsConfigPath, TLS or basic auth could be enabled.
//
// Deprecated: Use ListenAndServe instead.
func Listen(server *http.Server, flags *FlagConfig, logger *slog.Logger) error {
	return ListenAndServe(server, flags, logger)
}
