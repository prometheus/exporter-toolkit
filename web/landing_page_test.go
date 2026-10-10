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

func landingPageBody(t *testing.T, c LandingConfig) string {
	t.Helper()
	h, err := NewLandingPage(c)
	if err != nil {
		t.Fatalf("NewLandingPage: %v", err)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("got status %d, expected %d", rec.Code, http.StatusOK)
	}
	return rec.Body.String()
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
		},
	})

	for _, want := range []string{
		`href="/metrics"`,
		// "&" is written as "&amp;" in an HTML attribute; browsers decode it
		// back to a single "&" when following the link.
		`href="/probe?module=http_2xx&amp;target=example.com"`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("landing page does not contain %q", want)
		}
	}
}

// TestLandingPageCSSIsRendered checks that the generated stylesheet reaches the
// page unescaped, including the configured header color.
func TestLandingPageCSSIsRendered(t *testing.T) {
	body := landingPageBody(t, LandingConfig{Name: "test_exporter", HeaderColor: "#123456"})

	if !strings.Contains(body, "background-color: #123456;") {
		t.Error("header color was not rendered into the stylesheet")
	}
	if strings.Contains(body, "ZgotmplZ") {
		t.Error("stylesheet was escaped as an HTML value")
	}
}

// TestLandingPageServeHTTPNotFound checks that only the route prefix is served.
func TestLandingPageServeHTTPNotFound(t *testing.T) {
	h, err := NewLandingPage(LandingConfig{Name: "test_exporter"})
	if err != nil {
		t.Fatalf("NewLandingPage: %v", err)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/nope", nil))
	if rec.Code != http.StatusNotFound {
		t.Errorf("got status %d, expected %d", rec.Code, http.StatusNotFound)
	}
}
