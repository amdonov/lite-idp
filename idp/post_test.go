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
	"bytes"
	"testing"

	"github.com/PuerkitoBio/goquery"
	"github.com/amdonov/lite-idp/model"
	"github.com/stretchr/testify/assert"
)

func TestIDP_sendPostResponse(t *testing.T) {
	i := &IDP{}
	getTestIDP(t, i)
	var b bytes.Buffer
	if err := i.sendPostResponse(&model.AuthnRequest{
		AssertionConsumerServiceURL: "testsvc",
	}, &model.User{}, &b, nil); err != nil {
		t.Fatal(err)
	}
	// Check to see if the response contained a form posting to the assertion consumer service
	// Load the HTML document
	doc, err := goquery.NewDocumentFromReader(bytes.NewReader(b.Bytes()))
	if err != nil {
		t.Fatal(err)
	}
	value, ok := doc.Find("#samlpost").Attr("action")
	assert.True(t, ok, "failed to find form")
	assert.Equal(t, "testsvc", value, "assertion consumer service url doesn't match")
}
