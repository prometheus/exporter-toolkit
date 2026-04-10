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
// +build !genassets

//go:generate go run -tags genassets gen_assets.go

package web

import (
	"bytes"
	_ "embed"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/pprof"
	"net/url"
	"os"
	"path"
	"strings"
	"text/template"
)

// Config represents the configuration of the web listener.
type LandingConfig struct {
	RoutePrefix      string         // The route prefix for the exporter.
	ExternalURL      string         // The external URL for the exporter.
	ListenAddresses  []string       // The listen address for the exporter.
	UseSystemdSocket bool           // Use systemd socket.
	HeaderColor      string         // Used for the landing page header.
	CSS              string         // CSS style tag for the landing page.
	Name             string         // The name of the exporter, generally suffixed by _exporter.
	Description      string         // A short description about the exporter.
	Form             LandingForm    // A POST form.
	Links            []LandingLinks // Links displayed on the landing page.
	ExtraHTML        string         // Additional HTML to be embedded.
	ExtraCSS         string         // Additional CSS to be embedded.
	Version          string         // The version displayed.
	Logger           Logger         // Logging interface
}

type Logger interface {
	Error(msg string, keysAndValues ...interface{})
	Info(msg string, keysAndValues ...interface{})
	Debug(msg string, keysAndValues ...interface{})
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
	pprofMux    *http.ServeMux
}

var (
	//go:embed landing_page.html
	landingPagehtmlContent string
	//go:embed landing_page.css
	landingPagecssContent string
)

func NewLandingPage(c LandingConfig) (*LandingPageHandler, string, error) {
	var buf bytes.Buffer

	c.Form.Action = strings.TrimPrefix(c.Form.Action, "/")

	// Setup URL and Prefix logic
	if c.ExternalURL == "" && c.UseSystemdSocket {
		return nil, "", fmt.Errorf("cannot automatically infer external URL with systemd socket listener")
	}

	if c.ExternalURL == "" && len(c.ListenAddresses) > 1 {
		c.Logger.Info("Inferring external URL from first provided listen address")
	}

	if len(c.ListenAddresses) == 0 {
		return nil, "", fmt.Errorf("no listen addresses provided")
	}

	// Compute external URL
	var parsedExternalURL *url.URL
	var err error
	if c.ExternalURL == "" {
		hostname, err := os.Hostname()
		if err != nil {
			return nil, "", err
		}
		_, port, err := net.SplitHostPort(c.ListenAddresses[0])
		if err != nil {
			return nil, "", err
		}
		c.ExternalURL = fmt.Sprintf("http://%s:%s/", hostname, port)
	}

	if strings.HasPrefix(c.ExternalURL, "\"") || strings.HasPrefix(c.ExternalURL, "'") ||
		strings.HasSuffix(c.ExternalURL, "\"") || strings.HasSuffix(c.ExternalURL, "'") {
		return nil, "", errors.New("URL must not begin or end with quotes")
	}

	parsedExternalURL, err = url.Parse(c.ExternalURL)
	if err != nil {
		return nil, "", fmt.Errorf("failed to determine external URL: %w", err)
	}

	// Ensure Path component of ExternalURL is formatted without trailing slashes,
	// contains a leading slash, and is not empty
	pathPrefix := strings.TrimRight(parsedExternalURL.Path, "/")
	if pathPrefix != "" && !strings.HasPrefix(pathPrefix, "/") {
		pathPrefix = "/" + pathPrefix
	}
	parsedExternalURL.Path = pathPrefix

	if c.RoutePrefix == "" {
		c.RoutePrefix = parsedExternalURL.Path
		c.Logger.Info("RoutePrefix is empty, defaulting to ExternalURL path", "url", parsedExternalURL.Path)
	} else {
		c.Logger.Info("RoutePrefix is set", "RoutePrefix", c.RoutePrefix)
	}

	c.RoutePrefix = "/" + strings.Trim(c.RoutePrefix, "/")
	if c.RoutePrefix != "/" {
		c.RoutePrefix += "/"
	}

	if c.RoutePrefix == "" {
		c.RoutePrefix = "/"
	} else if !strings.HasSuffix(c.RoutePrefix, "/") {
		c.RoutePrefix += "/"
	}

	// Validate RoutePrefix
	if !strings.HasPrefix(c.RoutePrefix, "/") {
		return nil, "", fmt.Errorf("route prefix must start with '/'")
	}

	// Redirect over externalURL for root path only if routePrefix is different from "/"
	if c.RoutePrefix != "/" {
		http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != "/" {
				http.NotFound(w, r)
				return
			}
			http.Redirect(w, r, parsedExternalURL.String(), http.StatusFound)
		})
	}

	length := 0
	for _, input := range c.Form.Inputs {
		inputLength := len(input.Label)
		if inputLength > length {
			length = inputLength
		}
	}

	c.Form.Width = (float64(length) + 1) / 2
	if c.CSS == "" {
		if c.HeaderColor == "" {
			// Default to Prometheus orange.
			c.HeaderColor = "#e6522c"
		}
		cssTemplate := template.Must(template.New("landing css").Parse(landingPagecssContent))
		if err := cssTemplate.Execute(&buf, c); err != nil {
			return nil, "", err
		}
		c.CSS = buf.String()
	}
	if c.RoutePrefix == "" {
		c.RoutePrefix = "/"
	} else if !strings.HasSuffix(c.RoutePrefix, "/") {
		c.RoutePrefix += "/"
	}

	if c.Profiling == "" {
		c.Profiling = "true"
	}
	// Strip leading '/' from Links if present
	for i, link := range c.Links {
		c.Links[i].Address = strings.TrimPrefix(link.Address, "/")
	}
	t := template.Must(template.New("landing page").Parse(landingPagehtmlContent))

	buf.Reset()
	if err := t.Execute(&buf, c); err != nil {
		return nil, "", err
	}

	// Create a new ServeMux for pprof endpoints in the LandingPage
	pprofMux := http.NewServeMux()
	pprofMux.HandleFunc(path.Join(c.RoutePrefix, "debug/pprof/profile"), pprof.Profile)
	pprofMux.HandleFunc(path.Join(c.RoutePrefix, "debug/pprof/heap"), pprof.Handler("heap").ServeHTTP)

	return &LandingPageHandler{
		landingPage: buf.Bytes(),
		routePrefix: c.RoutePrefix,
		pprofMux:    pprofMux,
	}, c.RoutePrefix, nil
}

func (h *LandingPageHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if strings.HasPrefix(r.URL.Path, path.Join(h.routePrefix, "debug/pprof/")) {
		h.pprofMux.ServeHTTP(w, r)
		return
	}
	if r.URL.Path != h.routePrefix {
		http.NotFound(w, r)
		return
	}
	w.Header().Add("Content-Type", "text/html; charset=UTF-8")
	w.Write(h.landingPage)
}
