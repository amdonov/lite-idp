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
	"encoding/xml"
	"errors"
	"fmt"
	"io"

	"github.com/amdonov/lite-idp/saml"
	"github.com/wrouesnel/certutils"
)

// ServiceProvider stores the Service Provider metadata required by the IdP
type ServiceProvider struct {
	EntityID                  string
	AssertionConsumerServices []AssertionConsumerService
	Certificate               string
	// Could be an RSA or DSA public key
	publicKey interface{}
}

func (sp *ServiceProvider) parseCertificate() error {
	certs, err := certutils.LoadCertificatesFromPem([]byte(sp.Certificate))
	if err != nil {
		return fmt.Errorf("failed to parse certificates: %W", err)
	}

	if len(certs) > 1 {
		return errors.New("only 1 certificate should be presented per service provider")
	}

	if len(certs) == 0 {
		return errors.New("no certificates read from provided PEM block")
	}

	cert := certs[0]

	sp.publicKey = cert.PublicKey
	return nil
}

// AssertionConsumerService is a SAML assertion consumer service
type AssertionConsumerService struct {
	Index     uint32
	IsDefault bool
	Binding   string
	Location  string
}

// ReadSPMetadata reads XML metadata from a reader
func ReadSPMetadata(metadata io.Reader) (*ServiceProvider, error) {
	decoder := xml.NewDecoder(metadata)
	sp := &saml.SPEntityDescriptor{}
	if err := decoder.Decode(sp); err != nil {
		return nil, err
	}
	return convertMetadata(sp)
}

func convertMetadata(spMeta *saml.SPEntityDescriptor) (*ServiceProvider, error) {
	if spMeta == nil {
		return nil, errors.New("service provider entity descriptor not found")
	}
	x509Data := spMeta.SPSSODescriptor.KeyDescriptor.KeyInfo.X509Data
	if x509Data == nil {
		return nil, errors.New("service provider's SSO descriptor does not contain required X509Data element")
	}
	sp := &ServiceProvider{
		Certificate: x509Data.X509Certificate,
		EntityID:    spMeta.EntityDescriptor.EntityID,
	}
	sp.AssertionConsumerServices = make([]AssertionConsumerService, len(spMeta.SPSSODescriptor.AssertionConsumerService))
	for i, val := range spMeta.SPSSODescriptor.AssertionConsumerService {
		sp.AssertionConsumerServices[i] = AssertionConsumerService{
			Index:     val.Index,
			IsDefault: val.IsDefault,
			Binding:   val.Binding,
			Location:  val.Location,
		}
	}
	return sp, nil
}
