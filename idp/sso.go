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
	"encoding/base64"
	"encoding/xml"
	"errors"
	"fmt"
	"net/http"
	"net/url"

	"github.com/amdonov/lite-idp/model"
	"github.com/amdonov/lite-idp/saml"
	"github.com/golang/protobuf/proto"
	"github.com/google/uuid"
	log "github.com/sirupsen/logrus"
)

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
			err = decoder.Decode(loginReq)

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
