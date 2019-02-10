// Copyright © 2019 David Morgan <dmorgan81@gmail.com>
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
	"bytes"
	"encoding/xml"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/amdonov/lite-idp/model"
	"github.com/amdonov/lite-idp/saml"
)

func Test_sendECPResponse(t *testing.T) {
	i := &IDP{}
	ts := getTestIDP(t, i)
	defer ts.Close()

	var b bytes.Buffer
	if err := i.sendECPResponse(&model.AuthnRequest{
		AssertionConsumerServiceURL: "testsvc",
	}, &model.User{}, &b, nil); err != nil {
		t.Fatal(err)
	}

	var e saml.ECPResponseEnvelope
	decoder := xml.NewDecoder(&b)
	if err := decoder.Decode(&e); err != nil {
		t.Fatal(err)
	}

	assert.Equal(t, "testsvc", e.Header.ECPResponse.AssertionConsumerServiceURL, "assertion consumer service url doesn't match")
}
