// Copyright 2021 The Prometheus Authors
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

package basicauth

import (
	"fmt"
	"testing"
)

// TestCacheSize validates that makeRoom function caps the size of the cache
// appropriately.
func TestCacheSize(t *testing.T) {
	cache := newCache()
	expectedSize := 0
	for i := 0; i < 200; i++ {
		cache.set(fmt.Sprintf("foo%d", i), true)
		expectedSize++
		if expectedSize > 100 {
			expectedSize = 90
		}

		if gotSize := len(cache.cache); gotSize != expectedSize {
			t.Fatalf("iter %d: cache size invalid: expected %d, got %d", i, expectedSize, gotSize)
		}
	}
}
