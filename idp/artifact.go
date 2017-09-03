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
	"encoding/gob"
	"encoding/xml"
	"net/http"
	"time"

	"github.com/amdonov/lite-idp/saml"
)

func (i *idp) ArtifactResolve() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		decoder := xml.NewDecoder(r.Body)
		var resolveEnv saml.ArtifactResolveEnvelope
		err := decoder.Decode(&resolveEnv)
		// TODO confirm appropriate error response for this service
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		// TODO validate resolveEnv before proceeding
		artifact := resolveEnv.Body.ArtifactResolve.Artifact
		var response saml.Response
		data, err := i.tempCache.Get(artifact)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		gobDecoder := gob.NewDecoder(bytes.NewReader(data))
		err = gobDecoder.Decode(&response)
		// TODO confirm appropriate error response for this service
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		artResponseEnv := saml.ArtifactResponseEnvelope{}
		artResponse := &artResponseEnv.Body.ArtifactResponse
		artResponse.ID = saml.NewID()
		now := time.Now()
		artResponse.IssueInstant = now
		artResponse.InResponseTo = resolveEnv.Body.ArtifactResolve.ID
		artResponse.Version = "2.0"
		artResponse.Issuer = &saml.Issuer{
			Value: i.configuration.EntityID,
		}
		artResponse.Status = &saml.Status{
			StatusCode: saml.StatusCode{
				Value: "urn:oasis:names:tc:SAML:2.0:status:Success",
			},
		}
		artResponse.Response = response

		signature, err := i.signer.CreateSignature(response.Assertion)
		// TODO confirm appropriate error response for this service
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		response.Assertion.Signature = signature
		// TODO handle these errors. Probably can't do anything besides log, as we've already started to write the
		// response.
		_, err = w.Write([]byte(xml.Header))
		encoder := xml.NewEncoder(w)
		err = encoder.Encode(artResponseEnv)
		err = encoder.Flush()
	}
}
