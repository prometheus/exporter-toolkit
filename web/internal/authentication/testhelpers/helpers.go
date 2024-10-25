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

package testhelpers

import (
	"context"
	"log/slog"
	"net/http"
	"testing"
)

func NewNoOpLogger() *slog.Logger {
	return slog.New(&noOpHandler{})
}

type noOpHandler struct{}

var _ slog.Handler = &noOpHandler{}

func (h *noOpHandler) Enabled(_ context.Context, _ slog.Level) bool {
	return false
}

func (h *noOpHandler) Handle(_ context.Context, _ slog.Record) error {
	return nil
}

func (h *noOpHandler) WithAttrs(_ []slog.Attr) slog.Handler {
	return h
}

func (h *noOpHandler) WithGroup(_ string) slog.Handler {
	return h
}

func MakeDefaultRequest(t *testing.T) *http.Request {
	t.Helper()

	req, err := http.NewRequest(http.MethodGet, "/", nil)
	if err != nil {
		t.Fatalf("Error creating request: %v", err)
	}

	return req
}
