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

func NewIssuer(issuer string) *Issuer {
	return &Issuer{Format: "urn:oasis:names:tc:SAML:2.0:nameid-format:entity", Value: issuer}
}

func NewAttributeStatement(attributes map[string][]string) *AttributeStatement {
	if attributes == nil {
		return nil
	}
	stmt := &AttributeStatement{}
	for key, values := range attributes {
		att := Attribute{}
		att.FriendlyName = key
		att.Name = key
		att.NameFormat = "urn:oasis:names:tc:SAML:2.0:attrname-format:basic"
		for index := range values {
			val := AttributeValue{Value: values[index]}
			att.AttributeValue = append(att.AttributeValue, val)
		}
		stmt.Attribute = append(stmt.Attribute, att)
	}
	return stmt
}
