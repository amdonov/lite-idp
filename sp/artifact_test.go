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
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/amdonov/lite-idp/idp"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
)

func Test_serviceProvider_resolveArtifact(t *testing.T) {
	viper.Set("tls-certificate", filepath.Join("testdata", "certificate.pem"))
	viper.Set("tls-private-key", filepath.Join("testdata", "key.pem"))

	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// TODO check incoming request
		f, _ := os.Open(filepath.Join("testdata", "artifact-response.xml"))
		defer f.Close()
		io.Copy(w, f)
	}))

	tlsConfigClient, err := idp.ConfigureTLS()
	if err != nil {
		t.Fatal(err)
	}
	serviceProvide, err := New(Configuration{
		EntityID:                    "https://test/",
		AssertionConsumerServiceURL: "http://test",
		Client:                      ts.Client(),
		IDPArtifactEndpoint:         ts.URL,
		TLSConfig:                   tlsConfigClient,
	})
	assertion, err := serviceProvide.(*serviceProvider).resolveArtifact("12345")
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, "user@mail.example.org", assertion.Subject.NameID.Value, "subject is not correct")
}
