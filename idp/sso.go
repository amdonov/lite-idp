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

	"github.com/amdonov/lite-idp/model"
	"github.com/amdonov/lite-idp/saml"
	"github.com/golang/protobuf/proto"
	"github.com/google/uuid"
	log "github.com/sirupsen/logrus"
)

func (i *idp) SSOService() (http.HandlerFunc, error) {
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
			// check for cookie to see if user has a current session
			// check to see if they presented a client cert

			// need to display the login form
			// save the request
			saveableRequest := &model.AuthnRequest{}
			err = saveableRequest.Populate(loginReq, relayState)
			if err != nil {
				return err
			}
			data, err := proto.Marshal(saveableRequest)
			if err != nil {
				return err
			}
			id := uuid.New().String()
			err = i.tempCache.Set(id, data)
			if err != nil {
				return err
			}
			http.Redirect(w, r, fmt.Sprintf("/ui/login.html#%s", id), http.StatusTemporaryRedirect)
			return nil
		}()
		if err != nil {
			log.Error(err)
			http.Error(w, err.Error(), http.StatusBadRequest)
		}
	}, nil
}
