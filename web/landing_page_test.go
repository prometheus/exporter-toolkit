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
	"html/template"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// serveLandingPage builds a landing page from c, requests path from it and
// fails the test unless the response has status wantStatus.
func serveLandingPage(t *testing.T, c LandingConfig, path string, wantStatus int) string {
	t.Helper()
	h, err := NewLandingPage(c)
	if err != nil {
		t.Fatalf("NewLandingPage: %v", err)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
	if rec.Code != wantStatus {
		t.Fatalf("got status %d, expected %d", rec.Code, wantStatus)
	}
	return rec.Body.String()
}

func landingPageBody(t *testing.T, c LandingConfig) string {
	t.Helper()
	return serveLandingPage(t, c, "/", http.StatusOK)
}

// TestLandingPageEscapesConfiguredValues checks that values interpolated into
// the landing page are HTML-escaped. Exporters put non-constant data such as a
// probe target or a version string into these fields, so rendering them
// verbatim would be an injection point.
func TestLandingPageEscapesConfiguredValues(t *testing.T) {
	const payload = `</div><script>alert(1)</script>`

	body := landingPageBody(t, LandingConfig{
		Name:        payload,
		Description: payload,
		Version:     payload,
		Links: []LandingLinks{{
			Address:     `/metrics"><script>alert(2)</script>`,
			Text:        payload,
			Description: payload,
		}},
		Form: LandingForm{
			Action: "/probe",
			Inputs: []LandingFormInput{{
				Label:       payload,
				Type:        "text",
				Name:        payload,
				Placeholder: payload,
				Value:       payload,
			}},
		},
	})

	for _, unwanted := range []string{
		"<script>alert(1)</script>",
		"<script>alert(2)</script>",
	} {
		if strings.Contains(body, unwanted) {
			t.Errorf("landing page contains unescaped %q", unwanted)
		}
	}
	if !strings.Contains(body, "&lt;script&gt;") {
		t.Error("landing page does not contain the escaped payload at all")
	}
}

// TestLandingPageKeepsExtraHTMLAndCSS checks that the two fields documented as
// carrying markup are still emitted verbatim.
func TestLandingPageKeepsExtraHTMLAndCSS(t *testing.T) {
	body := landingPageBody(t, LandingConfig{
		Name:      "test_exporter",
		ExtraHTML: template.HTML(`<p class="extra">extra &amp; html</p>`),
		ExtraCSS:  template.CSS(`.extra { color: #e6522c; }`),
	})

	if !strings.Contains(body, `<p class="extra">extra &amp; html</p>`) {
		t.Error("ExtraHTML was not emitted verbatim")
	}
	if !strings.Contains(body, `.extra { color: #e6522c; }`) {
		t.Error("ExtraCSS was not emitted verbatim")
	}
}

// TestLandingPageKeepsLinkQueryStrings checks that ordinary link addresses,
// including query strings, survive escaping intact.
func TestLandingPageKeepsLinkQueryStrings(t *testing.T) {
	body := landingPageBody(t, LandingConfig{
		Name: "test_exporter",
		Links: []LandingLinks{
			{Address: "/metrics", Text: "Metrics"},
			{Address: "/probe?module=http_2xx&target=example.com", Text: "Probe"},
			// A colon in the first path segment must not be mistaken for a
			// URL scheme.
			{Address: "/probe?target=localhost:9100", Text: "Probe port"},
		},
		Form: LandingForm{Action: "/probe?target=localhost:9100"},
	})

	for _, want := range []string{
		`href="/metrics"`,
		// "&" is written as "&amp;" in an HTML attribute; browsers decode it
		// back to a single "&" when following the link.
		`href="/probe?module=http_2xx&amp;target=example.com"`,
		`href="/probe?target=localhost:9100"`,
		`action="/probe?target=localhost:9100"`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("landing page does not contain %q", want)
		}
	}
}

// TestLandingPageRoutePrefix checks that link and form targets are resolved
// against the route prefix, and that the caller's links are not modified.
func TestLandingPageRoutePrefix(t *testing.T) {
	links := []LandingLinks{{Address: "/metrics", Text: "Metrics"}}
	body := serveLandingPage(t, LandingConfig{
		Name:        "test_exporter",
		RoutePrefix: "/prefix",
		Links:       links,
		Form:        LandingForm{Action: "/probe"},
	}, "/prefix/", http.StatusOK)

	for _, want := range []string{
		`href="/prefix/metrics"`,
		`action="/prefix/probe"`,
		`href="/prefix/debug/pprof/heap"`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("landing page does not contain %q", want)
		}
	}
	if links[0].Address != "/metrics" {
		t.Errorf("caller's link address was modified to %q", links[0].Address)
	}
}

// TestLandingPageCSSIsRendered checks that the generated stylesheet reaches the
// page intact, including the configured header color and label width.
func TestLandingPageCSSIsRendered(t *testing.T) {
	body := landingPageBody(t, LandingConfig{
		Name:        "test_exporter",
		HeaderColor: "#123456",
		Form: LandingForm{
			Action: "/probe",
			Inputs: []LandingFormInput{{Label: "Target", Type: "text", Name: "target"}},
		},
	})

	for _, want := range []string{
		"background-color: #123456;",
		"width: 3.5em;",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("stylesheet does not contain %q", want)
		}
	}
	if strings.Contains(body, "ZgotmplZ") {
		t.Error("stylesheet value was rejected by the escaper")
	}
}

// TestLandingPageEscapesHeaderColor checks that the header color, which is
// interpolated into the stylesheet, cannot break out of the <style> element.
func TestLandingPageEscapesHeaderColor(t *testing.T) {
	body := landingPageBody(t, LandingConfig{
		Name:        "test_exporter",
		HeaderColor: `red}</style><script>alert(1)</script><style>`,
	})

	if strings.Contains(body, "<script>") {
		t.Error("landing page contains an unescaped <script> tag from HeaderColor")
	}
}

// TestLandingPageCustomCSS checks that a caller-supplied stylesheet replaces
// the default one.
func TestLandingPageCustomCSS(t *testing.T) {
	body := landingPageBody(t, LandingConfig{
		Name: "test_exporter",
		CSS:  template.CSS(`body { color: #abcdef; }`),
	})

	if !strings.Contains(body, `<style>body { color: #abcdef; }</style>`) {
		t.Error("custom CSS was not emitted verbatim")
	}
}

// TestLandingPageServeHTTPNotFound checks that only the route prefix is served.
func TestLandingPageServeHTTPNotFound(t *testing.T) {
	serveLandingPage(t, LandingConfig{Name: "test_exporter"}, "/nope", http.StatusNotFound)
}
