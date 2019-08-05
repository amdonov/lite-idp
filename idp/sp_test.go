// Copyright © 2017 Aaron Donovan <amdonov@gmail.com>
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package idp

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestReadSPMetadata(t *testing.T) {
	in, err := os.Open(filepath.Join("testdata", "sp-metadata.xml"))
	if err != nil {
		t.Fatal(err)
	}
	defer in.Close()
	sp, err := ReadSPMetadata(in)
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, "dex", sp.EntityID, "entity id is wrong")
}

func TestReadInvalidSPMetadata(t *testing.T) {
	in, err := os.Open(filepath.Join("testdata", "sp-metadata-invalid.xml"))
	if err != nil {
		t.Fatal(err)
	}
	defer in.Close()
	_, err = ReadSPMetadata(in)
	if err == nil {
		t.Fatal("expected failure")
	}
}
