// Copyright 2029 The Prometheus Authors
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

// +build !genassets
//go:generate go run -tags genassets gen_assets.go

package web

import (
	"image/color"
	"net/http"
)

// Config represents the configuration of the web listener.
type Config struct {
	Color       color.Color // Used for the landing page header.
	Name        string      // The name of the exporter, generally suffixed by _exporter.
	Description string      // A short description about the exporter.
}

type handler struct {
	config Config
}

func NewHandler(c Config) *handler {
	return &handler{
		config: c,
	}
}

func (h *handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
}
