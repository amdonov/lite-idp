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
	"net/url"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/amdonov/lite-idp/idp"
	"github.com/amdonov/lite-idp/saml"
	"github.com/amdonov/lite-idp/store"
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

func Test_serviceProvider_ArtifactFunc(t *testing.T) {
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
	callback := serviceProvider.ArtifactFunc(func(w http.ResponseWriter, r *http.Request, state []byte, assertion *saml.Assertion) {

	})
	ts := httptest.NewTLSServer(callback)
	defer ts.Close()
	resp, err := ts.Client().Get(ts.URL)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	assert.Equal(t, 401, resp.StatusCode, "expected invalid request")
}

func Test_serviceProvider_retrieveState(t *testing.T) {
	viper.Set("tls-certificate", filepath.Join("testdata", "certificate.pem"))
	viper.Set("tls-private-key", filepath.Join("testdata", "key.pem"))
	tlsConfigClient, err := idp.ConfigureTLS()
	if err != nil {
		t.Fatal(err)
	}
	cache, err := store.New(time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	sp, err := New(Configuration{
		EntityID:                    "https://test/",
		AssertionConsumerServiceURL: "http://test",
		TLSConfig:                   tlsConfigClient,
	})
	if err != nil {
		t.Fatal(err)
	}
	// make request without the cache
	req := httptest.NewRequest("GET", "/test", nil)
	req.Form = url.Values{}
	req.Form.Add("RelayState", "test")
	state, err := sp.(*serviceProvider).retrieveState(req)
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, []byte("test"), state)
	// rerun with a cache
	sp.(*serviceProvider).stateCache = cache
	cache.Set("test", []byte("cached-value"))
	state, err = sp.(*serviceProvider).retrieveState(req)
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, []byte("cached-value"), state)
}

func Test_serviceProvider_validateAssertion(t *testing.T) {
	viper.Set("tls-certificate", filepath.Join("testdata", "certificate.pem"))
	viper.Set("tls-private-key", filepath.Join("testdata", "key.pem"))
	tlsConfigClient, err := idp.ConfigureTLS()
	if err != nil {
		t.Fatal(err)
	}
	sp, err := New(Configuration{
		EntityID:                    "https://test/",
		AssertionConsumerServiceURL: "http://test",
		TLSConfig:                   tlsConfigClient,
	})
	// valid assertion
	assertion := &saml.Assertion{
		Conditions: &saml.Conditions{
			NotBefore:    time.Now(),
			NotOnOrAfter: time.Now().Add(time.Minute * 5),
		},
	}
	err = sp.(*serviceProvider).validateAssertion(assertion)
	assert.Equal(t, nil, err)
	// assertion that is before the NotBefore time
	assertion.Conditions.NotBefore = time.Now().Add(time.Hour * 5)
	err = sp.(*serviceProvider).validateAssertion(assertion)
	assert.NotEqual(t, nil, err)
	assert.Contains(t, err.Error(), "got response that cannot be processed before")
	// assertion that is after the NotOnOrAfter time
	assertion.Conditions.NotOnOrAfter = time.Now().Add(time.Hour * -5)
	err = sp.(*serviceProvider).validateAssertion(assertion)
	assert.NotEqual(t, nil, err)
	assert.Contains(t, err.Error(), "got response that cannot be processed because it expired at")
}

func Test_serviceProvider_validateAssertionWithThreshold(t *testing.T) {
	viper.Set("tls-certificate", filepath.Join("testdata", "certificate.pem"))
	viper.Set("tls-private-key", filepath.Join("testdata", "key.pem"))
	tlsConfigClient, err := idp.ConfigureTLS()
	if err != nil {
		t.Fatal(err)
	}
	sp, err := New(Configuration{
		EntityID:                    "https://test/",
		AssertionConsumerServiceURL: "http://test",
		TLSConfig:                   tlsConfigClient,
		TimestampMargin:             1 * time.Minute,
	})
	// valid assertion with the margin
	assertion := &saml.Assertion{
		Conditions: &saml.Conditions{
			NotBefore:    time.Now(),
			NotOnOrAfter: time.Now().Add(time.Minute * 5),
		},
	}
	err = sp.(*serviceProvider).validateAssertion(assertion)
	assert.Equal(t, nil, err)
	// assertion that is before the NotBefore time but the margin makes it pass
	assertion.Conditions.NotBefore = time.Now().Add(time.Minute * 1)
	err = sp.(*serviceProvider).validateAssertion(assertion)
	assert.Equal(t, nil, err)
	// assertion that is before the NotBefore time and past the margin
	assertion.Conditions.NotBefore = time.Now().Add(time.Minute * 5)
	err = sp.(*serviceProvider).validateAssertion(assertion)
	assert.NotEqual(t, nil, err)
	assert.Contains(t, err.Error(), "got response that cannot be processed before")
	// reset NotBefore
	assertion.Conditions.NotBefore = time.Now()
	// assertion that is after the NotOnOrAfter time but the margin makes it pass
	assertion.Conditions.NotOnOrAfter = time.Now().Add(time.Minute * -1)
	err = sp.(*serviceProvider).validateAssertion(assertion)
	assert.Equal(t, nil, err)
	// assertion that is after the NotOnOrAfter time and past the margin
	assertion.Conditions.NotOnOrAfter = time.Now().Add(time.Minute * -5)
	err = sp.(*serviceProvider).validateAssertion(assertion)
	assert.NotEqual(t, nil, err)
	assert.Contains(t, err.Error(), "got response that cannot be processed because it expired at")
}
