// Copyright 2020 The Prometheus Authors
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

// +build genassets

package main

import (
	"fmt"
	"io/ioutil"
	"os"
	"path"
	"path/filepath"
)

func main() {
	wd, err := os.Getwd()
	if err != nil {
		panic(err)
	}
	var assetsPrefix string
	switch path.Base(wd) {
	case "exporter-toolkit":
		// When running from the Makefile.
		assetsPrefix = "./web"
	case "web":
		// When running web tests.
		assetsPrefix = "./"
	}
	htmlContent, err := ioutil.ReadFile(filepath.Join(assetsPrefix, "index.html"))
	if err != nil {
		panic(err)
	}
	cssContent, err := ioutil.ReadFile(filepath.Join(assetsPrefix, "index.css"))
	if err != nil {
		panic(err)
	}

	err = ioutil.WriteFile(filepath.Join(assetsPrefix, "generated_assets.go"), []byte(fmt.Sprintf(`// Copyright 2020 The Prometheus Authors
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

package web

var htmlContent = `+"`%s`"+`
var cssContent = `+"`%s`", htmlContent, cssContent)), 0777)
	if err != nil {
		panic(err)
	}

}
