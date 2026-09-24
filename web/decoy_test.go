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
	"testing"

	config_util "github.com/prometheus/common/config"
	"golang.org/x/crypto/bcrypt"
)

func hashAtCost(t *testing.T, cost int) config_util.Secret {
	t.Helper()
	h, err := bcrypt.GenerateFromPassword([]byte("password"), cost)
	if err != nil {
		t.Fatalf("GenerateFromPassword: %v", err)
	}
	return config_util.Secret(h)
}

// TestMaxBcryptCost checks that the decoy cost tracks the most expensive
// configured user, so that a request for an unknown user is never answered
// faster than one for any configured user.
func TestMaxBcryptCost(t *testing.T) {
	cheap := hashAtCost(t, bcrypt.MinCost)
	mid := hashAtCost(t, bcrypt.MinCost+2)

	for _, tc := range []struct {
		name     string
		users    map[string]config_util.Secret
		expected int
	}{
		{
			name:     "no users",
			users:    nil,
			expected: bcrypt.MinCost,
		},
		{
			name:     "single user",
			users:    map[string]config_util.Secret{"alice": mid},
			expected: bcrypt.MinCost + 2,
		},
		{
			name:     "highest cost wins",
			users:    map[string]config_util.Secret{"alice": cheap, "bob": mid},
			expected: bcrypt.MinCost + 2,
		},
		{
			name:     "unparseable hashes are skipped",
			users:    map[string]config_util.Secret{"alice": "not a hash", "bob": mid},
			expected: bcrypt.MinCost + 2,
		},
		{
			name:     "only unparseable hashes",
			users:    map[string]config_util.Secret{"alice": "not a hash"},
			expected: bcrypt.MinCost,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := maxBcryptCost(tc.users); got != tc.expected {
				t.Errorf("maxBcryptCost() = %d, expected %d", got, tc.expected)
			}
		})
	}
}

// TestDecoyHashesForCost checks that the decoy carries the requested cost, which
// is what makes its comparison take as long as a configured user's, and that it
// is generated only once per cost.
func TestDecoyHashesForCost(t *testing.T) {
	d := newDecoyHashes()

	hash, err := d.forCost(bcrypt.MinCost)
	if err != nil {
		t.Fatalf("forCost: %v", err)
	}
	cost, err := bcrypt.Cost(hash)
	if err != nil {
		t.Fatalf("Cost: %v", err)
	}
	if cost != bcrypt.MinCost {
		t.Errorf("decoy cost = %d, expected %d", cost, bcrypt.MinCost)
	}

	again, err := d.forCost(bcrypt.MinCost)
	if err != nil {
		t.Fatalf("forCost: %v", err)
	}
	if string(again) != string(hash) {
		t.Error("forCost generated a second hash for a cost it had already produced")
	}
}

// TestDecoyHashesRejectsInvalidCost checks that an unusable cost is reported
// rather than silently producing a hash at some other cost.
func TestDecoyHashesRejectsInvalidCost(t *testing.T) {
	if _, err := newDecoyHashes().forCost(bcrypt.MaxCost + 1); err == nil {
		t.Error("expected an error for a cost above bcrypt.MaxCost")
	}
}
