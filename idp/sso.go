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
	"compress/flate"
	"crypto"
	"crypto/rsa"
	"crypto/sha1"
	"encoding/base64"
	"encoding/xml"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/amdonov/lite-idp/model"
	"github.com/amdonov/lite-idp/saml"
	"github.com/golang/protobuf/proto"
	"github.com/google/uuid"
	log "github.com/sirupsen/logrus"
)

func (i *IDP) validateRequest(request *saml.AuthnRequest, r *http.Request) error {
	// Only accept requests from registered service providers
	if request.Issuer == "" {
		return errors.New("request does not contain an issuer")
	}
	log.Infof("received authentication request from %s", request.Issuer)
	sp, ok := i.sps[request.Issuer]
	if !ok {
		return errors.New("request from an unregistered issuer")
	}
	// Determine the right assertion consumer service
	var acs *AssertionConsumerService
	for i, a := range sp.AssertionConsumerServices {
		// Find either the matching service or the default
		if a.Index == request.AssertionConsumerServiceIndex {
			acs = &sp.AssertionConsumerServices[i]
			break
		}
		if a.Location == request.AssertionConsumerServiceURL {
			acs = &sp.AssertionConsumerServices[i]
			break
		}
		if a.IsDefault {
			acs = &sp.AssertionConsumerServices[i]
		}
	}
	if acs == nil {
		return errors.New("unable to determine assertion consumer service")
	}
	// Don't allow a different URL than specified in the metadata
	if request.AssertionConsumerServiceURL == "" {
		request.AssertionConsumerServiceURL = acs.Location
	} else if request.AssertionConsumerServiceURL != acs.Location {
		return errors.New("assertion consumer location in request does not match metadata")
	}
	// At this point, we're OK with the request
	// Need to validate the signature
	// Have to use the raw query as pointed out in the spec.
	// https://docs.oasis-open.org/security/saml/v2.0/saml-bindings-2.0-os.pdf
	// Line 621

	// Split up the parts
	params := strings.Split(r.URL.RawQuery, "&")
	pMap := make(map[string]string, len(params))
	for i := range params {
		parts := strings.Split(params[i], "=")
		if len(parts) != 2 {
			return errors.New("trouble validating signature on request")
		}
		pMap[parts[0]] = parts[1]
	}
	// Order them
	sigparts := []string{fmt.Sprintf("SAMLRequest=%s", pMap["SAMLRequest"])}
	if state, ok := pMap["RelayState"]; ok {
		sigparts = append(sigparts, fmt.Sprintf("RelayState=%s", state))
	}
	sigparts = append(sigparts, fmt.Sprintf("SigAlg=%s", pMap["SigAlg"]))
	sig := []byte(strings.Join(sigparts, "&"))
	fmt.Println("REQUEST TO SIGN =======")
	fmt.Println(strings.Join(sigparts, "&"))
	fmt.Println("REQUEST TO SIGN =======")
	// Validate the signature
	switch r.Form.Get("SigAlg") {
	case "http://www.w3.org/2000/09/xmldsig#dsa-sha1":
		//return dsa.VerifyPKCS1v15(sp.publicKey.(*dsa.PublicKey), crypto.SHA1, sig, signature)
		return nil
	case "http://www.w3.org/2000/09/xmldsig#rsa-sha1":
		signature, err := base64.StdEncoding.DecodeString(r.Form.Get("Signature"))
		if err != nil {
			return err
		}
		h := sha1.New()
		h.Write(sig)
		sum := h.Sum(nil)
		return rsa.VerifyPKCS1v15(sp.publicKey.(*rsa.PublicKey), crypto.SHA1, sum, signature)
	default:
		return fmt.Errorf("unsupported signature algorithm, %s", r.Form.Get("SigAlg"))
	}
}

func (i *IDP) DefaultRedirectSSOHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		err := func() error {
			err := r.ParseForm()
			if err != nil {
				return err
			}
			relayState := r.Form.Get("RelayState")
			if len(relayState) > 80 {
				return errors.New("RelayState cannot be longer than 80 characters")
			}

			samlReq := r.Form.Get("SAMLRequest")
			// URL decoding is already performed
			// remove base64 encoding
			reqBytes, err := base64.StdEncoding.DecodeString(samlReq)
			if err != nil {
				return err
			}
			// Remove deflate
			req := flate.NewReader(bytes.NewReader(reqBytes))
			// Read the XML
			decoder := xml.NewDecoder(req)
			loginReq := &saml.AuthnRequest{}
			if err = decoder.Decode(loginReq); err != nil {
				return err
			}

			if err = i.validateRequest(loginReq, r); err != nil {
				return err
			}

			// create saveable request
			saveableRequest, err := model.NewAuthnRequest(loginReq, relayState)
			if err != nil {
				return err
			}

			// check for cookie to see if user has a current session
			if cookie, err := r.Cookie(i.cookieName); err == nil {
				// Found a session cookie
				if data, err := i.UserCache.Get(cookie.Value); err == nil {
					// Cookie matched user in cache
					user := &model.User{}
					if err = proto.Unmarshal(data, user); err == nil {
						log.Infof("found existing session for %s", user.Name)
						return i.respond(saveableRequest, user, w, r)
					}
				}
			}

			// check to see if they presented a client cert
			if clientCert, err := getCertFromRequest(r); err == nil {
				user := &model.User{
					Name:    getSubjectDN(clientCert.Subject),
					Format:  "urn:oasis:names:tc:SAML:1.1:nameid-format:X509SubjectName",
					Context: "urn:oasis:names:tc:SAML:2.0:ac:classes:X509",
					IP:      getIP(r).String()}

				// Add attributes
				err = i.setUserAttributes(user)
				if err != nil {
					return err
				}
				log.Infof("successful PKI login for %s", user.Name)
				return i.respond(saveableRequest, user, w, r)
			}
			// need to display the login form
			data, err := proto.Marshal(saveableRequest)
			if err != nil {
				return err
			}
			id := uuid.New().String()
			err = i.TempCache.Set(id, data)
			if err != nil {
				return err
			}
			http.Redirect(w, r, fmt.Sprintf("/ui/login.html?requestId=%s",
				url.QueryEscape(id)), http.StatusTemporaryRedirect)
			return nil
		}()
		if err != nil {
			log.Error(err)
			http.Error(w, err.Error(), http.StatusBadRequest)
		}
	}
}
