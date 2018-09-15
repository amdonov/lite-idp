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
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestIDP_DefaultMetadataHandler(t *testing.T) {
	ts := getTestIDP(t, &IDP{})
	// try to get server metadata
	resp, err := ts.Client().Get(ts.URL + "/metadata")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	assert.Equal(t, 200, resp.StatusCode, "metadata not found")
}
