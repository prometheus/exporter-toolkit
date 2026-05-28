# Web configuration

Exporters and services instrumented with the Exporter Toolkit share the same
web configuration file format. This is *experimental* and might change in the
future.

To specify which web configuration file to load, use the `--web.config.file` flag.

The file is written in [YAML format](https://en.wikipedia.org/wiki/YAML),
defined by the scheme described below.
Brackets indicate that a parameter is optional. For non-list parameters the
value is set to the specified default.

The file is read upon every http request, such as any change in the
configuration, so the certificates are picked up immediately.

Generic placeholders are defined as follows:

* `<boolean>`: a boolean that can take the values `true` or `false`
* `<filename>`: a valid path in the current working directory
* `<secret>`: a regular string that is a secret, such as a password
* `<string>`: a regular string
* `<int>`: a regular integer

```
tls_server_config:
  # Certificate for server to use to authenticate to client.
  # Expected to be passed as a PEM encoded sequence of bytes as a string.
  #
  # NOTE: If passing the cert inline, cert_file should not be specified below.
  [ cert: <string> ]

  # Key for server to use to authenticate to client.
  # Expected to be passed as a PEM encoded sequence of bytes as a string.
  #
  # NOTE: If passing the key inline, key_file should not be specified below.
  [ key: <secret> ]

  # CA certificate for client certificate authentication to the server.
  # Expected to be passed as a PEM encoded sequence of bytes as a string.
  #
  # NOTE: If passing the client_ca inline, client_ca_file should not be specified below.
  [ client_ca: <string> ]

  # Certificate and key files for server to use to authenticate to client.
  cert_file: <filename>
  key_file: <filename>

  # Server policy for client authentication. Maps to ClientAuth Policies.
  # For more detail on clientAuth options:
  # https://golang.org/pkg/crypto/tls/#ClientAuthType
  #
  # NOTE: If you want to enable client authentication, you need to use
  # RequireAndVerifyClientCert. Other values are insecure.
  [ client_auth_type: <string> | default = "NoClientCert" ]

  # CA certificate for client certificate authentication to the server.
  [ client_ca_file: <filename> ]

  # Verify that the client certificate has a Subject Alternate Name (SAN)
  # which is an exact match to an entry in this list, else terminate the
  # connection. SAN match can be one or multiple of the following: DNS,
  # IP, e-mail, or URI address from https://pkg.go.dev/crypto/x509#Certificate.
  [ client_allowed_sans:
    [ - <string> ] ]

  # Minimum TLS version that is acceptable.
  [ min_version: <string> | default = "TLS12" ]

  # Maximum TLS version that is acceptable.
  [ max_version: <string> | default = "TLS13" ]

  # List of supported cipher suites for TLS versions up to TLS 1.2. If empty,
  # Go default cipher suites are used. Available cipher suites are documented
  # in the go documentation:
  # https://golang.org/pkg/crypto/tls/#pkg-constants
  #
  # Note that only the cipher returned by the following function are supported:
  # https://pkg.go.dev/crypto/tls#CipherSuites
  [ cipher_suites:
    [ - <string> ] ]

  # prefer_server_cipher_suites controls whether the server selects the
  # client's most preferred ciphersuite, or the server's most preferred
  # ciphersuite. If true then the server's preference, as expressed in
  # the order of elements in cipher_suites, is used.
  [ prefer_server_cipher_suites: <bool> | default = true ]

  # Elliptic curves that will be used in an ECDHE handshake, in preference
  # order. Available curves are documented in the go documentation:
  # https://golang.org/pkg/crypto/tls/#CurveID
  [ curve_preferences:
    [ - <string> ] ]

http_server_config:
  # Enable HTTP/2 support. Note that HTTP/2 is only supported with TLS.
  # This can not be changed on the fly.
  [ http2: <boolean> | default = true ]
  # List of headers that can be added to HTTP responses.
  [ headers:
    # Set the Content-Security-Policy header to HTTP responses.
    # Unset if blank.
    [ Content-Security-Policy: <string> ]
    # Set the X-Frame-Options header to HTTP responses.
    # Unset if blank. Accepted values are deny and sameorigin.
    # https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options
    [ X-Frame-Options: <string> ]
    # Set the X-Content-Type-Options header to HTTP responses.
    # Unset if blank. Accepted value is nosniff.
    # https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Content-Type-Options
    [ X-Content-Type-Options: <string> ]
    # Set the X-XSS-Protection header to all responses.
    # Unset if blank.
    # https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-XSS-Protection
    [ X-XSS-Protection: <string> ]
    # Set the Strict-Transport-Security header to HTTP responses.
    # Unset if blank.
    # Please make sure that you use this with care as this header might force
    # browsers to load Prometheus and the other applications hosted on the same
    # domain and subdomains over HTTPS.
    # https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security
    [ Strict-Transport-Security: <string> ] ]

# Usernames and hashed passwords that have full access to the web
# server via basic authentication. If empty, no basic authentication is
# required. Passwords are hashed with bcrypt.
basic_auth_users:
  [ <string>: <secret> ... ]


# Rate limiting requests on the endpoint using a token bucket
rate_limit:
  interval: <duration> # time interval between two requests, set to 0 to disable rate limiter
  burst: <int> # and permits a burst of <int> requests.

# IP-layer socket options applied to the listening socket.
# All fields are optional; an omitted field uses the kernel default.
ip_socket_config:
  # IPv4 TTL on outbound packets. Valid: 1-255.
  # Lower values bound how far response packets can travel; useful as a
  # defense-in-depth measure (e.g. ttl=2 means packets die after two
  # router hops). On Linux this is inherited by accepted connections
  # (accept(2), ip(7)).
  [ ipv4_ttl: <int> ]

  # IPv6 Hop Limit on outbound packets. Valid: 1-255. Same semantics as
  # ipv4_ttl but for IPv6.
  [ ipv6_hop_limit: <int> ]

  # DSCP codepoint applied to outbound packets via IPv4 ToS and IPv6
  # Traffic Class (upper 6 bits). Valid: 0-63. Common values:
  # 0 (CS0, best-effort), 8 (CS1), 16 (CS2), 26 (AF31), 46 (EF).
  # The 2 ECN bits (lower 2 bits of the ToS byte) are NOT touched --
  # the kernel manages them per-packet for ECN-capable TCP (RFC 3168).
  [ dscp: <int> ]
```

[A sample configuration file](web-config.yml) is provided.

## About `ip_socket_config`

The `ip_socket_config` block sets IP-layer header fields on the listening
socket. Each option can also be set via a CLI flag or environment variable
(`--web.ipv4-ttl` / `WEB_IPV4_TTL`, `--web.ipv6-hop-limit` /
`WEB_IPV6_HOP_LIMIT`, `--web.dscp` / `WEB_DSCP`); the flag wins when both
the flag and a YAML value are set.

Listener-flavor support:

| Listener | TTL / Hop Limit | DSCP |
|---|---|---|
| Regular TCP | Set on the listening socket via `net.ListenConfig.Control`; inherited by accepted connections. | Set per accepted connection (IP_TOS / IPV6_TCLASS are *not* inherited from the listener on Linux). |
| Systemd socket activation | Set on the systemd-provided listener post-bind via `setsockopt`. | Set per accepted connection (same as regular TCP). |
| VSOCK | Ignored (VSOCK has no IP layer); an info-level log line is emitted if any option is configured. | Same — ignored. |

Platform support:

| Platform | Status |
|---|---|
| Linux | Fully supported, CI-tested. |
| FreeBSD / DragonFly / NetBSD / OpenBSD / Darwin | Compile-supported via `golang.org/x/sys/unix`; not CI-tested. |
| Windows / Plan 9 / JS+Wasm / others | No-op. The first time any IP socket option is configured, a single warn-level log line is emitted and the configured values are ignored. |

Operator notes:

* The minimum useful TTL is **1** (packet dies at the first router; reach is
  limited to the local L2 segment). TTL=0 is rejected by configuration
  validation — it is forbidden by RFC 1122 §3.2.1.7 and Linux overloads
  `setsockopt(IP_TTL, 0)` to mean "use the kernel default" anyway.
* DSCP=0 (CS0) is a valid configured value and is honored; it is *not* the
  "not configured" sentinel. Omit the field if you don't want to set DSCP.
* On dual-stack listeners (e.g. `[::]:9100`) both the IPv4 and IPv6 socket
  options are set; the kernel applies the appropriate one per outbound
  packet.

## About bcrypt

There are several tools out there to generate bcrypt passwords, e.g.
[htpasswd](https://httpd.apache.org/docs/2.4/programs/htpasswd.html):

`htpasswd -nBC 10 "" | tr -d ':\n'`

That command will prompt you for a password and output the hashed password,
which will look something like:
`$2y$10$X0h1gDsPszWURQaxFh.zoubFi6DXncSjhoQNJgRrnGs7EsimhC7zG`

The cost (10 in the example) influences the time it takes for computing the
hash. A higher cost will end up slowing down the authentication process.
Depending on the machine, a cost of 10 will take about ~70ms, whereas a cost of
18 can take up to a few seconds. That hash will be computed on the first
authenticated HTTP request and then cached.

## Performance

Basic authentication is meant for simple use cases, with a few users.  If you
need to authenticate a lot of users, it is recommended to use TLS client
certificates, or to use a proper reverse proxy to handle the authentication.
