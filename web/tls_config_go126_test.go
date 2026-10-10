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

//go:build go1.26

package web

import (
	"crypto/tls"
	"testing"
)

func TestGo126CurvePreferences(t *testing.T) {
	for name, want := range map[string]tls.CurveID{
		"SecP256r1MLKEM768":  tls.SecP256r1MLKEM768,
		"SecP384r1MLKEM1024": tls.SecP384r1MLKEM1024,
	} {
		t.Run(name, func(t *testing.T) {
			var got Curve
			err := got.UnmarshalYAML(func(value any) error {
				*value.(*string) = name
				return nil
			})
			if err != nil {
				t.Fatalf("could not parse curve preference: %v", err)
			}
			if actual := tls.CurveID(got); actual != want {
				t.Fatalf("got curve ID %v, want %v", actual, want)
			}

			encoded, err := got.MarshalYAML()
			if err != nil {
				t.Fatalf("could not marshal curve preference: %v", err)
			}
			if actual, ok := encoded.(string); !ok || actual != name {
				t.Fatalf("got marshaled curve %v, want %q", encoded, name)
			}
		})
	}
}
