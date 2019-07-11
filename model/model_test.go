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

package model

import (
	"encoding/xml"
	"os"
	"path/filepath"
	"testing"

	"github.com/amdonov/lite-idp/saml"
	"github.com/stretchr/testify/assert"
)

func TestNewAuthnRequest(t *testing.T) {
	in, err := os.Open(filepath.Join("testdata", "authn-request.xml"))
	if err != nil {
		t.Fatal(err)
	}
	defer in.Close()
	dec := xml.NewDecoder(in)
	req := &saml.AuthnRequest{}
	dec.Decode(req)
	modelReq, err := NewAuthnRequest(req, "1234")
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, "http://sp.example.com/demo1/metadata.php", modelReq.GetIssuer(), "issuer doesn't match")
}

func TestUser_AttributeStatement(t *testing.T) {
	user := &User{Name: "joe"}
	user.AppendAttributes([]*Attribute{
		{Name: "age", Value: []string{"9"}},
		{Name: "sn", Value: []string{"Mama"}},
		{Name: "email", Value: []string{"joe@gmail.com"}},
	})
	statement := user.AttributeStatement()
	assert.Equal(t, 3, len(statement.Attribute), "expected 3 attributes")
}
