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

package sp

import (
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/amdonov/lite-idp/idp"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
)

func Test_serviceProvider_MetadataFunc(t *testing.T) {
	viper.Set("tls-certificate", filepath.Join("testdata", "certificate.pem"))
	viper.Set("tls-private-key", filepath.Join("testdata", "key.pem"))
	tlsConfigClient, err := idp.ConfigureTLS()
	if err != nil {
		t.Fatal(err)
	}
	serviceProvider, err := New(Configuration{
		EntityID:                    "https://test/",
		AssertionConsumerServiceURL: "http://test",
		TLSConfig:                   tlsConfigClient,
	})
	mf, err := serviceProvider.MetadataFunc()
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewTLSServer(mf)
	defer ts.Close()
	resp, err := ts.Client().Get(ts.URL)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	assert.Equal(t, 200, resp.StatusCode, "failed to get sp metadata")
}
