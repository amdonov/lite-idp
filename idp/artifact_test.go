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
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/amdonov/lite-idp/model"
	"github.com/golang/protobuf/proto"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
)

func TestIDP_DefaultArtifactResolveHandler(t *testing.T) {
	i := &IDP{}
	i.ArtifactResolveHandler = i.processArtifactResolutionRequest
	ts := getTestIDP(t, i)
	defer ts.Close()
	in, err := os.Open(filepath.Join("testdata", "artifact-resolve-request.xml"))
	if err != nil {
		t.Fatal(err)
	}
	// Need to cache user before attempting an artifact resolve
	req := &model.ArtifactResponse{
		Request: &model.AuthnRequest{},
		User:    &model.User{},
	}
	data, err := proto.Marshal(req)
	if err != nil {
		t.Fatal(err)
	}
	i.TempCache.Set("123456", data)
	resp, err := ts.Client().Post(ts.URL+viper.GetString("artifact-service-path"), "text/xml", in)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	assert.Equal(t, 200, resp.StatusCode, "failed to resolve artifact")
}

func TestIDP_sendArtifactResponse(t *testing.T) {
	i := &IDP{}
	getTestIDP(t, i)
	i.sendArtifactResponse(&model.AuthnRequest{}, &model.User{}, httptest.NewRecorder(), httptest.NewRequest("GET", "/test", nil))
}
