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

//go:build go1.14
// +build go1.14

package web

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"sync"
	"testing"
	"time"
)

// Helpers for literal FlagConfig
func OfBool(i bool) *bool {
	return &i
}
func OfString(i string) *string {
	return &i
}

var (
	port       = getPort()
	testlogger = &testLogger{}

	ErrorMap = map[string]*regexp.Regexp{
		"HTTP Response to HTTPS":       regexp.MustCompile(`server gave HTTP response to HTTPS client`),
		"No such file":                 regexp.MustCompile(`no such file`),
		"Invalid argument":             regexp.MustCompile(`invalid argument`),
		"YAML error":                   regexp.MustCompile(`yaml`),
		"Invalid ClientAuth":           regexp.MustCompile(`invalid ClientAuth`),
		"TLS handshake":                regexp.MustCompile(`tls`),
		"HTTP Request to HTTPS server": regexp.MustCompile(`HTTP`),
		"Invalid CertPath":             regexp.MustCompile(`missing cert_file`),
		"Invalid KeyPath":              regexp.MustCompile(`missing key_file`),
		"ClientCA set without policy":  regexp.MustCompile(`Client CA's have been configured without a Client Auth Policy`),
		"Bad password":                 regexp.MustCompile(`hashedSecret too short to be a bcrypted password`),
		"Unauthorized":                 regexp.MustCompile(`Unauthorized`),
		"Forbidden":                    regexp.MustCompile(`Forbidden`),
		"Handshake failure":            regexp.MustCompile(`handshake failure`),
		"Unknown cipher":               regexp.MustCompile(`unknown cipher`),
		"Unknown curve":                regexp.MustCompile(`unknown curve`),
		"Unknown TLS version":          regexp.MustCompile(`unknown TLS version`),
		"No HTTP2 cipher":              regexp.MustCompile(`TLSConfig.CipherSuites is missing an HTTP/2-required`),
		// The first token is returned by Go <= 1.17 and the second token is returned by Go >= 1.18.
		"Incompatible TLS version": regexp.MustCompile(`protocol version not supported|no supported versions satisfy MinVersion and MaxVersion`),
		"Bad certificate":          regexp.MustCompile(`Unauthorized`),
		"Invalid value":            regexp.MustCompile(`invalid value for`),
		"Invalid header":           regexp.MustCompile(`HTTP header ".*" can not be configured`),
		"Invalid client cert":      regexp.MustCompile(`Unauthorized`),
	}
)

type testLogger struct{}

func (t *testLogger) Log(keyvals ...interface{}) error {
	return nil
}

func getPort() string {
	listener, err := net.Listen("tcp", ":0")
	if err != nil {
		panic(err)
	}
	defer listener.Close()
	p := listener.Addr().(*net.TCPAddr).Port
	return fmt.Sprintf(":%v", p)
}

type TestInputs struct {
	Name                string
	Server              func() *http.Server
	YAMLConfigPath      string
	ExpectedError       *regexp.Regexp
	UseTLSClient        bool
	ClientMaxTLSVersion uint16
	CipherSuites        []uint16
	ActualCipher        uint16
	CurvePreferences    []tls.CurveID
	Username            string
	Password            string
	ClientCertificate   string
	URI                 string
}

func TestYAMLFiles(t *testing.T) {
	testTables := []*TestInputs{
		{
			Name:           `path to config yml invalid`,
			YAMLConfigPath: "somefile",
			ExpectedError:  ErrorMap["No such file"],
		},
		{
			Name:           `empty config yml`,
			YAMLConfigPath: "testdata/web_config_empty.yml",
			ExpectedError:  nil,
		},
		{
			Name:           `invalid config yml (invalid structure)`,
			YAMLConfigPath: "testdata/web_config_junk.yml",
			ExpectedError:  ErrorMap["YAML error"],
		},
		{
			Name:           `invalid config yml (invalid key)`,
			YAMLConfigPath: "testdata/web_config_junk_key.yml",
			ExpectedError:  ErrorMap["YAML error"],
		},
		{
			Name:           `invalid config yml (cert path empty)`,
			YAMLConfigPath: "testdata/web_config_noAuth_certPath_empty.bad.yml",
			ExpectedError:  ErrorMap["Invalid CertPath"],
		},
		{
			Name:           `invalid config yml (key path empty)`,
			YAMLConfigPath: "testdata/web_config_noAuth_keyPath_empty.bad.yml",
			ExpectedError:  ErrorMap["Invalid KeyPath"],
		},
		{
			Name:           `invalid config yml (cert path and key path empty)`,
			YAMLConfigPath: "testdata/web_config_noAuth_certPath_keyPath_empty.bad.yml",
			ExpectedError:  ErrorMap["Invalid CertPath"],
		},
		{
			Name:           `invalid config yml (cert path invalid)`,
			YAMLConfigPath: "testdata/web_config_noAuth_certPath_invalid.bad.yml",
			ExpectedError:  ErrorMap["No such file"],
		},
		{
			Name:           `invalid config yml (key path invalid)`,
			YAMLConfigPath: "testdata/web_config_noAuth_keyPath_invalid.bad.yml",
			ExpectedError:  ErrorMap["No such file"],
		},
		{
			Name:           `invalid config yml (cert path and key path invalid)`,
			YAMLConfigPath: "testdata/web_config_noAuth_certPath_keyPath_invalid.bad.yml",
			ExpectedError:  ErrorMap["No such file"],
		},
		{
			Name:           `invalid config yml (invalid ClientAuth)`,
			YAMLConfigPath: "testdata/web_config_noAuth.bad.yml",
			ExpectedError:  ErrorMap["ClientCA set without policy"],
		},
		{
			Name:           `invalid config yml (invalid ClientCAs filepath)`,
			YAMLConfigPath: "testdata/web_config_auth_clientCAs_invalid.bad.yml",
			ExpectedError:  ErrorMap["No such file"],
		},
		{
			Name:           `invalid config yml (invalid user list)`,
			YAMLConfigPath: "testdata/web_config_auth_user_list_invalid.bad.yml",
			ExpectedError:  ErrorMap["Bad password"],
		},
		{
			Name:           `invalid config yml (bad cipher)`,
			YAMLConfigPath: "testdata/web_config_noAuth_inventedCiphers.bad.yml",
			ExpectedError:  ErrorMap["Unknown cipher"],
		},
		{
			Name:           `invalid config yml (bad curves)`,
			YAMLConfigPath: "testdata/web_config_noAuth_inventedCurves.bad.yml",
			ExpectedError:  ErrorMap["Unknown curve"],
		},
		{
			Name:           `invalid config yml (bad TLS version)`,
			YAMLConfigPath: "testdata/web_config_noAuth_wrongTLSVersion.bad.yml",
			ExpectedError:  ErrorMap["Unknown TLS version"],
		},
	}
	for _, testInputs := range testTables {
		t.Run("run/"+testInputs.Name, testInputs.Test)
		t.Run("validate/"+testInputs.Name, testInputs.TestValidate)
	}
}

func TestServerBehaviour(t *testing.T) {
	testTables := []*TestInputs{
		{
			Name:           `empty string YAMLConfigPath and default client`,
			YAMLConfigPath: "",
			ExpectedError:  nil,
		},
		{
			Name:           `empty string YAMLConfigPath and TLS client`,
			YAMLConfigPath: "",
			UseTLSClient:   true,
			ExpectedError:  ErrorMap["HTTP Response to HTTPS"],
		},
		{
			Name:           `valid tls config yml and default client`,
			YAMLConfigPath: "testdata/web_config_noAuth.good.yml",
			ExpectedError:  ErrorMap["HTTP Request to HTTPS server"],
		},
		{
			Name:           `valid tls config yml and tls client`,
			YAMLConfigPath: "testdata/web_config_noAuth.good.yml",
			UseTLSClient:   true,
			ExpectedError:  nil,
		},
		{
			Name:                `valid tls config yml with TLS 1.1 client`,
			YAMLConfigPath:      "testdata/web_config_noAuth.good.yml",
			UseTLSClient:        true,
			ClientMaxTLSVersion: tls.VersionTLS11,
			ExpectedError:       ErrorMap["Incompatible TLS version"],
		},
		{
			Name:           `valid tls config yml with all ciphers`,
			YAMLConfigPath: "testdata/web_config_noAuth_allCiphers.good.yml",
			UseTLSClient:   true,
			ExpectedError:  nil,
		},
		{
			Name:           `valid tls config yml with some ciphers`,
			YAMLConfigPath: "testdata/web_config_noAuth_someCiphers.good.yml",
			UseTLSClient:   true,
			CipherSuites:   []uint16{tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256},
			ExpectedError:  nil,
		},
		{
			Name:           `valid tls config yml with no common cipher`,
			YAMLConfigPath: "testdata/web_config_noAuth_someCiphers.good.yml",
			UseTLSClient:   true,
			CipherSuites:   []uint16{tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA},
			ExpectedError:  ErrorMap["Handshake failure"],
		},
		{
			Name:           `valid tls config yml with multiple client ciphers`,
			YAMLConfigPath: "testdata/web_config_noAuth_someCiphers.good.yml",
			UseTLSClient:   true,
			CipherSuites: []uint16{
				tls.TLS_RSA_WITH_AES_128_CBC_SHA,
				tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			},
			ActualCipher:  tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			ExpectedError: nil,
		},
		{
			Name:           `valid tls config yml with multiple client ciphers, client chooses cipher`,
			YAMLConfigPath: "testdata/web_config_noAuth_someCiphers_noOrder.good.yml",
			UseTLSClient:   true,
			CipherSuites: []uint16{
				tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
				tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			},
			ActualCipher:  tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			ExpectedError: nil,
		},
		{
			Name:           `valid tls config yml with all curves`,
			YAMLConfigPath: "testdata/web_config_noAuth_allCurves.good.yml",
			UseTLSClient:   true,
			ExpectedError:  nil,
		},
		{
			Name:             `valid tls config yml with some curves`,
			YAMLConfigPath:   "testdata/web_config_noAuth_someCurves.good.yml",
			UseTLSClient:     true,
			CurvePreferences: []tls.CurveID{tls.CurveP521},
			ExpectedError:    nil,
		},
		{
			Name:             `valid tls config yml with no common curves`,
			YAMLConfigPath:   "testdata/web_config_noAuth_someCurves.good.yml",
			UseTLSClient:     true,
			CurvePreferences: []tls.CurveID{tls.CurveP384},
			ExpectedError:    ErrorMap["Handshake failure"],
		},
		{
			Name:           `valid tls config yml with non-http2 ciphers`,
			YAMLConfigPath: "testdata/web_config_noAuth_noHTTP2.good.yml",
			UseTLSClient:   true,
			ExpectedError:  nil,
		},
		{
			Name:           `valid tls config yml with non-http2 ciphers but http2 enabled`,
			YAMLConfigPath: "testdata/web_config_noAuth_noHTTP2Cipher.bad.yml",
			UseTLSClient:   true,
			ExpectedError:  ErrorMap["No HTTP2 cipher"],
		},
		{
			Name:           `valid tls config yml and tls client with RequireAnyClientCert`,
			YAMLConfigPath: "testdata/tls_config_noAuth.requireanyclientcert.good.yml",
			UseTLSClient:   true,
			ExpectedError:  ErrorMap["Bad certificate"],
		},
		{
			Name:           `valid headers config`,
			YAMLConfigPath: "testdata/web_config_headers.good.yml",
		},
		{
			Name:           `invalid X-Content-Type-Options headers config`,
			YAMLConfigPath: "testdata/web_config_headers_content_type_options.bad.yml",
			ExpectedError:  ErrorMap["Invalid value"],
		},
		{
			Name:           `invalid X-Frame-Options headers config`,
			YAMLConfigPath: "testdata/web_config_headers_frame_options.bad.yml",
			ExpectedError:  ErrorMap["Invalid value"],
		},
		{
			Name:           `HTTP header that can not be overridden`,
			YAMLConfigPath: "testdata/web_config_headers_extra_header.bad.yml",
			ExpectedError:  ErrorMap["Invalid header"],
		},
		{
			Name:              `valid tls config yml and tls client with RequireAnyClientCert (present certificate)`,
			YAMLConfigPath:    "testdata/tls_config_noAuth.requireanyclientcert.good.yml",
			UseTLSClient:      true,
			ClientCertificate: "client_selfsigned",
			ExpectedError:     nil,
		},
		{
			Name:           `valid tls config yml and tls client with RequireAndVerifyClientCert`,
			YAMLConfigPath: "testdata/tls_config_noAuth.requireandverifyclientcert.good.yml",
			UseTLSClient:   true,
			ExpectedError:  ErrorMap["Bad certificate"],
		},
		{
			Name:              `valid tls config yml and tls client with RequireAndVerifyClientCert (present certificate)`,
			YAMLConfigPath:    "testdata/tls_config_noAuth.requireandverifyclientcert.good.yml",
			UseTLSClient:      true,
			ClientCertificate: "client_selfsigned",
			ExpectedError:     nil,
		},
		{
			Name:              `valid tls config yml and tls client with RequireAndVerifyClientCert (present wrong certificate)`,
			YAMLConfigPath:    "testdata/tls_config_noAuth.requireandverifyclientcert.good.yml",
			UseTLSClient:      true,
			ClientCertificate: "client2_selfsigned",
			ExpectedError:     ErrorMap["Bad certificate"],
		},
		{
			Name:              `valid tls config yml and tls client with VerifyPeerCertificate (present good SAN DNS entry)`,
			YAMLConfigPath:    "testdata/web_config_auth_client_san.good.yaml",
			UseTLSClient:      true,
			ClientCertificate: "client2_selfsigned",
			ExpectedError:     nil,
		},
		{
			Name:              `valid tls config yml and tls client with VerifyPeerCertificate (present invalid SAN DNS entries)`,
			YAMLConfigPath:    "testdata/web_config_auth_client_san.bad.yaml",
			UseTLSClient:      true,
			ClientCertificate: "client2_selfsigned",
			ExpectedError:     ErrorMap["Invalid client cert"],
		},
		{
			Name:           `valid tls config yml and tls client with RequireAndVerifyClientCert and auth_excluded_paths (path not matching, certificate not present)`,
			YAMLConfigPath: "testdata/tls_config_noAuth.requireandverifyclientcert.authexcludedpaths.good.yml",
			UseTLSClient:   true,
			URI:            "/someotherpath",
			ExpectedError:  ErrorMap["Unauthorized"],
		},
		{
			Name:              `valid tls config yml and tls client with RequireAndVerifyClientCert and auth_excluded_paths (path not matching, certificate present)`,
			YAMLConfigPath:    "testdata/tls_config_noAuth.requireandverifyclientcert.authexcludedpaths.good.yml",
			UseTLSClient:      true,
			ClientCertificate: "client_selfsigned",
			URI:               "/someotherpath",
			ExpectedError:     nil,
		},
		{
			Name:           `valid tls config yml and tls client with RequireAndVerifyClientCert and auth_excluded_paths (path matching, certificate not present)`,
			YAMLConfigPath: "testdata/tls_config_noAuth.requireandverifyclientcert.authexcludedpaths.good.yml",
			UseTLSClient:   true,
			URI:            "/somepath",
			ExpectedError:  nil,
		},
		{
			Name:              `valid tls config yml and tls client with RequireAndVerifyClientCert and auth_excluded_paths (path matching, wrong certificate present)`,
			YAMLConfigPath:    "testdata/tls_config_noAuth.requireandverifyclientcert.authexcludedpaths.good.yml",
			UseTLSClient:      true,
			ClientCertificate: "client2_selfsigned",
			URI:               "/somepath",
			ExpectedError:     nil,
		},
		{
			Name:              `valid tls config yml and tls client with VerifyPeerCertificate and auth_excluded_paths (path matching, present invalid SAN DNS entries)`,
			YAMLConfigPath:    "testdata/web_config_auth_client_san.authexcludedpaths.bad.yaml",
			UseTLSClient:      true,
			ClientCertificate: "client2_selfsigned",
			URI:               "/somepath",
			ExpectedError:     nil,
		},
		{
			Name:              `valid tls config yml and tls client with VerifyPeerCertificate and auth_excluded_paths (path not matching, present invalid SAN DNS entries)`,
			YAMLConfigPath:    "testdata/web_config_auth_client_san.authexcludedpaths.bad.yaml",
			UseTLSClient:      true,
			ClientCertificate: "client2_selfsigned",
			URI:               "/someotherpath",
			ExpectedError:     ErrorMap["Invalid client cert"],
		},
	}
	for _, testInputs := range testTables {
		t.Run(testInputs.Name, testInputs.Test)
	}
}

func TestConfigReloading(t *testing.T) {
	errorChannel := make(chan error, 1)
	var once sync.Once
	recordConnectionError := func(err error) {
		once.Do(func() {
			errorChannel <- err
		})
	}
	defer func() {
		if recover() != nil {
			recordConnectionError(errors.New("Panic in test function"))
		}
	}()

	goodYAMLPath := "testdata/web_config_noAuth.good.yml"
	badYAMLPath := "testdata/web_config_noAuth.good.blocking.yml"

	server := &http.Server{
		Addr: port,
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Write([]byte("Hello World!"))
		}),
	}
	defer func() {
		server.Close()
	}()

	go func() {
		defer func() {
			if recover() != nil {
				recordConnectionError(errors.New("Panic starting server"))
			}
		}()
		flagsBadYAMLPath := FlagConfig{
			WebListenAddresses: &([]string{port}),
			WebSystemdSocket:   OfBool(false),
			WebConfigFile:      OfString(badYAMLPath),
		}
		err := Listen(server, &flagsBadYAMLPath, testlogger)
		recordConnectionError(err)
	}()

	client := getTLSClient("")

	TestClientConnection := func() error {
		time.Sleep(250 * time.Millisecond)
		r, err := client.Get("https://localhost" + port)
		if err != nil {
			return err
		}
		body, err := io.ReadAll(r.Body)
		if err != nil {
			return err
		}
		if string(body) != "Hello World!" {
			return errors.New(string(body))
		}
		return nil
	}

	err := TestClientConnection()
	if err == nil {
		recordConnectionError(errors.New("connection accepted but should have failed"))
	} else {
		swapFileContents(goodYAMLPath, badYAMLPath)
		defer swapFileContents(goodYAMLPath, badYAMLPath)
		err = TestClientConnection()
		if err != nil {
			recordConnectionError(errors.New("connection failed but should have been accepted"))
		} else {

			recordConnectionError(nil)
		}
	}

	err = <-errorChannel
	if err != nil {
		t.Errorf(" *** Failed test: %s *** Returned error: %v", "TestConfigReloading", err)
	}
}

func (test *TestInputs) Test(t *testing.T) {
	errorChannel := make(chan error, 1)
	var once sync.Once
	recordConnectionError := func(err error) {
		once.Do(func() {
			errorChannel <- err
		})
	}
	defer func() {
		if recover() != nil {
			recordConnectionError(errors.New("Panic in test function"))
		}
	}()

	server := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Write([]byte("Hello World!"))
		}),
	}
	t.Cleanup(func() { server.Close() })
	go func() {
		defer func() {
			if recover() != nil {
				recordConnectionError(errors.New("Panic starting server"))
			}
		}()
		flags := FlagConfig{
			WebListenAddresses: &([]string{port}),
			WebSystemdSocket:   OfBool(false),
			WebConfigFile:      &test.YAMLConfigPath,
		}
		err := ListenAndServe(server, &flags, testlogger)
		recordConnectionError(err)
	}()

	ClientConnection := func() (*http.Response, error) {
		var client *http.Client
		var proto string
		if test.UseTLSClient {
			client = getTLSClient(test.ClientCertificate)
			t := client.Transport.(*http.Transport)
			t.TLSClientConfig.MaxVersion = test.ClientMaxTLSVersion
			if len(test.CipherSuites) > 0 {
				t.TLSClientConfig.CipherSuites = test.CipherSuites
			}
			if len(test.CurvePreferences) > 0 {
				t.TLSClientConfig.CurvePreferences = test.CurvePreferences
			}
			proto = "https"
		} else {
			client = http.DefaultClient
			proto = "http"
		}
		path, err := url.JoinPath(proto+"://localhost"+port, test.URI)
		if err != nil {
			t.Fatalf("Can't join url path: %v", err)
		}
		req, err := http.NewRequest("GET", path, nil)
		if err != nil {
			t.Error(err)
		}
		if test.Username != "" {
			req.SetBasicAuth(test.Username, test.Password)
		}
		return client.Do(req)
	}
	go func() {
		time.Sleep(250 * time.Millisecond)
		r, err := ClientConnection()
		if err != nil {
			recordConnectionError(err)
			return
		}

		if test.ActualCipher != 0 {
			if r.TLS.CipherSuite != test.ActualCipher {
				recordConnectionError(
					fmt.Errorf("bad cipher suite selected. Expected: %s, got: %s",
						tls.CipherSuiteName(test.ActualCipher),
						tls.CipherSuiteName(r.TLS.CipherSuite),
					),
				)
			}
		}

		body, err := io.ReadAll(r.Body)
		if err != nil {
			recordConnectionError(err)
			return
		}
		if string(body) != "Hello World!" {
			recordConnectionError(errors.New(string(body)))
			return
		}
		recordConnectionError(nil)
	}()
	err := <-errorChannel
	if test.isCorrectError(err) == false {
		if test.ExpectedError == nil {
			t.Logf("Expected no error, got error: %v", err)
		} else {
			t.Logf("Expected error matching regular expression: %v", test.ExpectedError)
			t.Logf("Got: %v", err)
		}
		t.Fail()
	}
}

func (test *TestInputs) TestValidate(t *testing.T) {
	validationErr := Validate(test.YAMLConfigPath)
	if test.ExpectedError == nil {
		if validationErr != nil {
			t.Errorf("Expected no error, got error: %v", validationErr)
		}
		return
	}
	if validationErr == nil {
		t.Errorf("Got no error, expected: %v", test.ExpectedError)
		return
	}
	if !test.ExpectedError.MatchString(validationErr.Error()) {
		t.Errorf("Expected error %v, got error: %v", test.ExpectedError, validationErr)
	}
}

func (test *TestInputs) isCorrectError(returnedError error) bool {
	switch {
	case returnedError == nil && test.ExpectedError == nil:
	case returnedError != nil && test.ExpectedError != nil && test.ExpectedError.MatchString(returnedError.Error()):
	default:
		return false
	}
	return true
}

func getTLSClient(clientCertName string) *http.Client {
	cert, err := os.ReadFile("testdata/tls-ca-chain.pem")
	if err != nil {
		panic("Unable to start TLS client. Check cert path")
	}

	var clientCertficate tls.Certificate
	if clientCertName != "" {
		clientCertficate, err = tls.LoadX509KeyPair(
			"testdata/"+clientCertName+".pem",
			"testdata/"+clientCertName+".key",
		)
		if err != nil {
			panic(fmt.Sprintf("failed to load client certificate: %v", err))
		}
	}

	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				RootCAs: func() *x509.CertPool {
					caCertPool := x509.NewCertPool()
					caCertPool.AppendCertsFromPEM(cert)
					return caCertPool
				}(),
				GetClientCertificate: func(req *tls.CertificateRequestInfo) (*tls.Certificate, error) {
					return &clientCertficate, nil
				},
			},
		},
	}
	return client
}

func swapFileContents(file1, file2 string) error {
	content1, err := os.ReadFile(file1)
	if err != nil {
		return err
	}
	content2, err := os.ReadFile(file2)
	if err != nil {
		return err
	}
	err = os.WriteFile(file1, content2, 0644)
	if err != nil {
		return err
	}
	err = os.WriteFile(file2, content1, 0644)
	if err != nil {
		return err
	}
	return nil
}

func TestUsers(t *testing.T) {
	testTables := []*TestInputs{
		{
			Name:           `without basic auth`,
			YAMLConfigPath: "testdata/web_config_users_noTLS.good.yml",
			ExpectedError:  ErrorMap["Unauthorized"],
		},
		{
			Name:           `with correct basic auth`,
			YAMLConfigPath: "testdata/web_config_users_noTLS.good.yml",
			Username:       "dave",
			Password:       "dave123",
			ExpectedError:  nil,
		},
		{
			Name:           `without basic auth and TLS`,
			YAMLConfigPath: "testdata/web_config_users.good.yml",
			UseTLSClient:   true,
			ExpectedError:  ErrorMap["Unauthorized"],
		},
		{
			Name:           `with correct basic auth and TLS`,
			YAMLConfigPath: "testdata/web_config_users.good.yml",
			UseTLSClient:   true,
			Username:       "dave",
			Password:       "dave123",
			ExpectedError:  nil,
		},
		{
			Name:           `with another correct basic auth and TLS`,
			YAMLConfigPath: "testdata/web_config_users.good.yml",
			UseTLSClient:   true,
			Username:       "carol",
			Password:       "carol123",
			ExpectedError:  nil,
		},
		{
			Name:           `with bad password and TLS`,
			YAMLConfigPath: "testdata/web_config_users.good.yml",
			UseTLSClient:   true,
			Username:       "dave",
			Password:       "bad",
			ExpectedError:  ErrorMap["Unauthorized"],
		},
		{
			Name:           `with bad username and TLS`,
			YAMLConfigPath: "testdata/web_config_users.good.yml",
			UseTLSClient:   true,
			Username:       "nonexistent",
			Password:       "nonexistent",
			ExpectedError:  ErrorMap["Unauthorized"],
		},
		{
			Name:           `with bad username, TLS and auth_excluded_paths (path not matching)`,
			YAMLConfigPath: "testdata/web_config_users.authexcludedpaths.good.yml",
			UseTLSClient:   true,
			Username:       "nonexistent",
			Password:       "nonexistent",
			URI:            "/someotherpath",
			ExpectedError:  ErrorMap["Unauthorized"],
		},
		{
			Name:           `with bad username, TLS and auth_excluded_paths (path matching)`,
			YAMLConfigPath: "testdata/web_config_users.authexcludedpaths.good.yml",
			UseTLSClient:   true,
			Username:       "nonexistent",
			Password:       "nonexistent",
			URI:            "/somepath",
			ExpectedError:  nil,
		},
	}
	for _, testInputs := range testTables {
		t.Run(testInputs.Name, testInputs.Test)
	}
}
