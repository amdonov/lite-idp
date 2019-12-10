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
	"encoding/xml"
	"errors"
	"io"
	"io/ioutil"
	"net/http"
	"strings"

	"github.com/amdonov/lite-idp/model"
	"github.com/amdonov/lite-idp/saml"
	log "github.com/sirupsen/logrus"
)

func (i *IDP) DefaultECPHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// We require transport authentication rather than message authentication
		tlsCert, err := getCertFromRequest(r)
		if tlsCert == nil || err != nil {
			i.Error(w, "403 Forbidden", http.StatusForbidden)
			return
		}
		log.Infof("received ecp request from %s", getSubjectDN(tlsCert.Subject))

		request, user, err := i.processECPRequest(w, r)
		if err != nil {
			sendSOAPFault(i, w, "SOAP-ENV:Client", err.Error())
			return
		}

		if err := i.respond(request, user, w, r); err != nil {
			sendSOAPFault(i, w, "SOAP-ENV:Server", err.Error())
			return
		}
	}
}

func sendSOAPFault(i *IDP, w http.ResponseWriter, code, fault string) {
	envelope := saml.SOAPFaultEnvelope{
		Body: saml.SOAPFaultBody{
			Fault: saml.SOAPFault{
				Code:   code,
				String: fault,
			},
		},
	}

	var b strings.Builder
	encoder := xml.NewEncoder(&b)
	_ = encoder.Encode(envelope)
	_ = encoder.Flush()

	i.Error(w, b.String(), http.StatusInternalServerError)
}

func (i *IDP) processECPRequest(w http.ResponseWriter, r *http.Request) (*model.AuthnRequest, *model.User, error) {
	xml, err := ioutil.ReadAll(r.Body)
	if err != nil {
		return nil, nil, err
	}

	authnReq, err := i.validateECPRequest(string(xml))
	if err != nil {
		return nil, nil, err
	}

	request, err := model.NewAuthnRequest(authnReq, "")
	if err != nil {
		return nil, nil, err
	}

	user, err := i.loginWithCert(r, request)
	if err != nil {
		return nil, nil, err
	}

	return request, user, nil
}

func (i *IDP) sendECPResponse(request *model.AuthnRequest, user *model.User, w io.Writer, r *http.Request) error {
	response := i.makeAuthnResponse(request, user)
	signature, err := i.signer.CreateSignature(response.Assertion)
	if err != nil {
		return err
	}
	response.Assertion.Signature = signature

	envelope := saml.ECPResponseEnvelope{
		Header: saml.ECPResponseHeader{
			ECPResponse: saml.ECPResponse{
				Actor:                       "http://schemas.xmlsoap.org/soap/actor/next",
				MustUnderstand:              1,
				AssertionConsumerServiceURL: request.AssertionConsumerServiceURL,
			},
			ECPRequestAuthenticated: saml.ECPRequestAuthenticated{
				Actor: "http://schemas.xmlsoap.org/soap/actor/next",
			},
		},
		Body: saml.ECPResponseBody{
			Response: *response,
		},
	}

	// start by writing the XML header
	_, _ = w.Write([]byte(xml.Header))

	// at this point we're successful so if an error happens during marshalling, oh well
	encoder := xml.NewEncoder(w)
	_ = encoder.Encode(envelope)
	_ = encoder.Flush()

	return nil
}

func (i *IDP) validateECPRequest(body string) (*saml.AuthnRequest, error) {
	// TODO verify channel bindings

	referenced, err := i.validator.Validate(body)
	if err != nil {
		return nil, err
	}

	// we should have just one AuthnRequest
	var authnReq saml.AuthnRequest
	decoder := xml.NewDecoder(strings.NewReader(referenced[0]))
	if err := decoder.Decode(&authnReq); err != nil {
		return nil, err
	}

	if authnReq.Issuer == "" {
		return nil, errors.New("request does not contain an issuer")
	}

	sp, ok := i.sps[authnReq.Issuer]
	if !ok {
		return nil, errors.New("request from unregistered issuer")
	}

	// Determine the right assertion consumer service
	var acs *AssertionConsumerService
	for _, a := range sp.AssertionConsumerServices {
		if a.Location == authnReq.AssertionConsumerServiceURL {
			acs = &a
			break
		}
		if a.IsDefault {
			acs = &a
			break
		}
	}
	if acs == nil {
		return nil, errors.New("unable to determine assertion consumer service")
	}
	if authnReq.AssertionConsumerServiceURL != acs.Location {
		return nil, errors.New("assertion consumer location in request does not match metadata")
	}

	return &authnReq, nil
}
