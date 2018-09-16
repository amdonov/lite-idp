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

	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
)

func TestIDP_DefaultRedirectSSOHandler(t *testing.T) {
	viper.Set("sps", []ServiceProvider{
		ServiceProvider{
			AssertionConsumerServices: []AssertionConsumerService{
				{
					Index:     0,
					IsDefault: true,
					Binding:   "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Artifact",
					Location:  "http://127.0.0.1:5556/dex/callback",
				},
			},
			EntityID:    "dex",
			Certificate: "MIICzDCCAbQCCQCaJRU/CzFSGzANBgkqhkiG9w0BAQsFADAoMQswCQYDVQQGEwJVUzEMMAoGA1UECgwDZGV4MQswCQYDVQQDDAJzcDAeFw0xODA5MDQxODEwMzlaFw0yODA5MDExODEwMzlaMCgxCzAJBgNVBAYTAlVTMQwwCgYDVQQKDANkZXgxCzAJBgNVBAMMAnNwMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAzJZd8K9jxC6mxuR5dw08qicw0VsDN1bAvdInKGzugsJYRH/MfcgrKwLCTZHBGZZFmdHxhca84cG/Wn24Ys5eF1JWhehYocyYqZqY3ESPldDK4ohwCvKhSogpF9hVyi9LnujCgfGOv98atMWDeqTLletCPsHcXzLq3cN58oNl80HXIQKFM7n9ZgUKLqk6d2hT7LeYndZKg5aUQ4jyTfz/S1XgYBDr0utl41HtUsHSYwQDx3v0wMqZVorzk8HrXaXowvUwVct6HxT/c5QxtHCxmm6n6/Mwr8Xzk1yxQq9dLtEOmEtnYgIEhyiUP7CdFPWC37sn9YiGCSjRukE07CyG0wIDAQABMA0GCSqGSIb3DQEBCwUAA4IBAQAJFl+hHwS6xNRtWMgJsu943zv4U8ZksyWAM5bk94ERMwpJVPndJIW0+UAT3Pp/k9E3Lro/AbSIA364LBzLoONOqfeNTUK4YH7wQGfmusI8c28akY5ZfDx8Ixc4oxPkcExh47YkVECSUhMq9gDMI10ePsSkVB7fss1QibmOsGM8WQyQzdmqfHbd7ws0g7P2I+SiR5+FboyliKRdqqSvQ8dL2hEAGtc9mZCPnlriiNzawCYPprH3lA+QWq+SI+QmQqTou05pWl5q+KcWU7INf0wEsXa26qcizqMTMNPuuu8Lp0gmmpUeH1AKVqO8P9VYT+GnkAUdoD3z1GCkLUvPaFYP",
		},
	})
	i := &IDP{}
	ts := getTestIDP(t, i)
	resp, err := ts.Client().Get(ts.URL + viper.GetString("sso-service-path") + "?SAMLRequest=fJFRi%2BIwEMe%2FSsh7mrS2Xhys0jsfTvBA1LvXI43pGrZN3cxU%2BvGX1RVcFnxMmN8w%2F99%2Fvhy7ll1cRN%2BHkqeJ4svFHE3XnqEa6BR27m1wSGy9Kvl%2FnU8b3UwykRa1FnlTWzGbZLWodZPnTWYLZTVn%2F%2B7bskRxtkYc3DogmUAlz1SqhZqJdHpQBagcilSoHJTibBt76m3f%2FvTh6MNLyYcYoDfoEYLpHAJZ2Fd%2FNpAlCurbEMLvw2Erqki%2BMZY4qxBdJN%2BHX33AoXNx7%2BLFW%2Fd3tyn5iegMUqbZj0QlKkmhKIqpPLpRWtO2tbGvnK0ckg%2BGrgG%2BAVppJc1AJxmdaTuUnUFyUZ4%2Fb5cf5jgbuzYgXC0%2Bj3HnHpHnhLkH5Lea4Oo3Lo5unMvHj9vra4uLdwAAAP%2F%2F&RelayState=ymktrbuodubogbc5gix6pyax5&SigAlg=http%3A%2F%2Fwww.w3.org%2F2000%2F09%2Fxmldsig%23rsa-sha1&Signature=FiWbe%2Fgui2UDb1FowmAudpNvX7ysQavigZ2j1C17E6TLYk9IsfV0nKY0shdKJZvBsceh5oGJAQDO5vUdLE29AUMdFvCYn1K90YI7Iu71ZBJdhh6veg6T5EW9cpQ%2FAalL66PU9J1IaF7vROElF0wJQNCMuMfwz1alug0d%2Fw49OtsSflZIIIQLYg9jRqIyoR4Qv4MdKLsYVJc5x3iyLNyu5tY01M5i5f%2FudgMxzGHg7hyM7AXbhJhBNMwuKxdC5A%2FIw72eFh0QIq%2Fb%2B%2BSgoMNpxCLtxnskk%2F5xoj3euNZntyKiL35VB6ZpXWku0uMd97ImRSrPgeRnXBltVcpiWLR1vg%3D%3D")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	assert.Equal(t, 200, resp.StatusCode, "expected login page from sso")
}
