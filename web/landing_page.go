// Copyright 2023 The Prometheus Authors
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

//go:build !genassets

//go:generate go run -tags genassets gen_assets.go

package web

import (
	"bytes"
	_ "embed"
	"html/template"
	"net/http"
	"strings"
)

// Config represents the configuration of the web listener.
type LandingConfig struct {
	RoutePrefix string         // The route prefix for the exporter.
	HeaderColor string         // Used for the landing page header.
	CSS         template.CSS   // CSS style tag for the landing page.
	Name        string         // The name of the exporter, generally suffixed by _exporter.
	Description string         // A short description about the exporter.
	Form        LandingForm    // A POST form.
	Links       []LandingLinks // Links displayed on the landing page.
	ExtraHTML   template.HTML  // Additional HTML to be embedded.
	ExtraCSS    template.CSS   // Additional CSS to be embedded.
	Version     string         // The version displayed.
	Profiling   string         // If false, don't display profiling links.
}

// LandingForm provides a configuration struct for creating a POST form on the landing page.
type LandingForm struct {
	Action string
	Inputs []LandingFormInput
	Width  float64
}

// LandingFormInput represents a single form input field.
type LandingFormInput struct {
	Label       string
	Type        string
	Name        string
	Placeholder string
	Value       string
}

type LandingLinks struct {
	Address     string // The URL the link points to.
	Text        string // The text of the link.
	Description string // A descriptive textfor the link.
}

type LandingPageHandler struct {
	landingPage []byte
	routePrefix string
}

var (
	//go:embed landing_page.html
	landingPagehtmlContent string
	//go:embed landing_page.css
	landingPagecssContent string
)

func NewLandingPage(c LandingConfig) (*LandingPageHandler, error) {
	c.Form.Action = strings.TrimPrefix(c.Form.Action, "/")

	length := 0
	for _, input := range c.Form.Inputs {
		inputLength := len(input.Label)
		if inputLength > length {
			length = inputLength
		}
	}
	c.Form.Width = (float64(length) + 1) / 2
	if c.HeaderColor == "" {
		// Default to Prometheus orange.
		c.HeaderColor = "#e6522c"
	}
	if c.RoutePrefix == "" {
		c.RoutePrefix = "/"
	} else if !strings.HasSuffix(c.RoutePrefix, "/") {
		c.RoutePrefix += "/"
	}

	if c.Profiling == "" {
		c.Profiling = "true"
	}
	// Resolve link and form targets against the route prefix here rather than
	// in the template: html/template only accepts the URL as safe when it sees
	// it whole. Copy the links so the caller's slice is left untouched.
	if c.Form.Action != "" {
		c.Form.Action = c.RoutePrefix + c.Form.Action
	}
	links := make([]LandingLinks, len(c.Links))
	for i, link := range c.Links {
		link.Address = c.RoutePrefix + strings.TrimPrefix(link.Address, "/")
		links[i] = link
	}
	c.Links = links
	t := template.Must(template.New("landing page").Parse(landingPagehtmlContent))
	// The default stylesheet is rendered inside the page's <style> element,
	// so html/template escapes the values it interpolates for CSS.
	template.Must(t.New("landing css").Parse(landingPagecssContent))

	var buf bytes.Buffer
	if err := t.Execute(&buf, c); err != nil {
		return nil, err
	}

	return &LandingPageHandler{
		landingPage: buf.Bytes(),
		routePrefix: c.RoutePrefix,
	}, nil
}

func (h *LandingPageHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != h.routePrefix {
		http.NotFound(w, r)
		return
	}
	w.Header().Add("Content-Type", "text/html; charset=UTF-8")
	w.Write(h.landingPage)
}
