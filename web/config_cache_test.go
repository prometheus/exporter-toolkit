// Copyright The Prometheus Authors
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
	"os"
	"path/filepath"
	"testing"
)

func writeConfigFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("Unable to write config: %v", err)
	}
}

func getConfigOrFail(t *testing.T, path string) *Config {
	t.Helper()
	c, err := getConfig(path)
	if err != nil {
		t.Fatalf("getConfig: %v", err)
	}
	return c
}

// TestGetConfigReloadsOnChange checks that an edited configuration file is
// picked up, which is what the per-request read exists for.
func TestGetConfigReloadsOnChange(t *testing.T) {
	path := filepath.Join(t.TempDir(), "web-config.yml")

	writeConfigFile(t, path, "http_server_config:\n  http2: true\n")
	if c := getConfigOrFail(t, path); !c.HTTPConfig.HTTP2 {
		t.Error("http2 = false, expected true")
	}

	writeConfigFile(t, path, "http_server_config:\n  http2: false\n  headers:\n    X-Frame-Options: deny\n")
	c := getConfigOrFail(t, path)
	if c.HTTPConfig.HTTP2 {
		t.Error("http2 = true after the file changed, expected false")
	}
	if got := c.HTTPConfig.Header["X-Frame-Options"]; got != "deny" {
		t.Errorf("X-Frame-Options = %q after the file changed, expected %q", got, "deny")
	}
}

// TestGetConfigReusesParsedConfig checks that an unchanged file is not parsed
// again. The cache keys on modification time and size, so the test rewrites the
// file with different content of the same length and restores the timestamps:
// the previously parsed configuration is expected to survive. This is also the
// documented limitation of the approach.
func TestGetConfigReusesParsedConfig(t *testing.T) {
	path := filepath.Join(t.TempDir(), "web-config.yml")

	writeConfigFile(t, path, "http_server_config:\n  http2: true\n")
	if c := getConfigOrFail(t, path); !c.HTTPConfig.HTTP2 {
		t.Fatal("http2 = false, expected true")
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("Stat: %v", err)
	}
	// Same length as the content above.
	writeConfigFile(t, path, "http_server_config:\n  http2: nope\n")
	if err := os.Chtimes(path, info.ModTime(), info.ModTime()); err != nil {
		t.Fatalf("Chtimes: %v", err)
	}

	c, err := getConfig(path)
	if err != nil {
		t.Fatalf("getConfig re-parsed a file it should have taken from the cache: %v", err)
	}
	if !c.HTTPConfig.HTTP2 {
		t.Error("http2 = false, expected the cached configuration")
	}
}

// TestGetConfigReturnsACopy checks that a caller cannot change what the next
// caller sees.
func TestGetConfigReturnsACopy(t *testing.T) {
	path := filepath.Join(t.TempDir(), "web-config.yml")
	writeConfigFile(t, path, "http_server_config:\n  http2: true\n")

	first := getConfigOrFail(t, path)
	first.HTTPConfig.HTTP2 = false

	if second := getConfigOrFail(t, path); !second.HTTPConfig.HTTP2 {
		t.Error("a change to one caller's configuration was visible to the next")
	}
}

// TestGetConfigDoesNotCacheFailures checks that a file which does not parse is
// reported every time, rather than once.
func TestGetConfigDoesNotCacheFailures(t *testing.T) {
	path := filepath.Join(t.TempDir(), "web-config.yml")
	writeConfigFile(t, path, "this is not a valid configuration\n")

	for i := range 2 {
		if _, err := getConfig(path); err == nil {
			t.Fatalf("getConfig call %d = nil, expected an error", i+1)
		}
	}
}

// TestGetConfigMissingFile checks that a missing file is still an error.
func TestGetConfigMissingFile(t *testing.T) {
	if _, err := getConfig(filepath.Join(t.TempDir(), "does-not-exist.yml")); err == nil {
		t.Error("getConfig() = nil, expected an error")
	}
}

func BenchmarkGetConfig(b *testing.B) {
	path := filepath.Join(b.TempDir(), "web-config.yml")
	content := "http_server_config:\n  headers:\n    X-Frame-Options: deny\n"
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		b.Fatalf("Unable to write config: %v", err)
	}

	b.ReportAllocs()
	for b.Loop() {
		if _, err := getConfig(path); err != nil {
			b.Fatal(err)
		}
	}
}
