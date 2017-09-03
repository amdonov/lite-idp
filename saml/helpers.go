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

package saml

import (
	"fmt"
	"net"

	"github.com/google/uuid"
)

type AuthenticatedUser struct {
	Name    string
	Format  string
	Context string
	IP      net.IP
}

func NewID() string {
	return fmt.Sprintf("_%s", uuid.New())
}

func NewIssuer(issuer string) *Issuer {
	return &Issuer{Format: "urn:oasis:names:tc:SAML:2.0:nameid-format:entity", Value: issuer}
}

func NewAttributeStatement(attributes map[string][]string) *AttributeStatement {
	if attributes == nil {
		return nil
	}
	stmt := &AttributeStatement{}
	for key, values := range attributes {
		attVals := make([]AttributeValue, len(values))
		for i := range values {
			attVals[i] = AttributeValue{Value: values[i]}
		}
		att := Attribute{
			FriendlyName:   key,
			Name:           key,
			NameFormat:     "urn:oasis:names:tc:SAML:2.0:attrname-format:basic",
			AttributeValue: attVals,
		}
		stmt.Attribute = append(stmt.Attribute, att)
	}
	return stmt
}
