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
	"bufio"
	"bytes"
	"encoding/base64"
	"encoding/xml"
	"io"
	"net/http"

	"github.com/amdonov/lite-idp/model"
)

func (i *IDP) sendPostResponse(authRequest *model.AuthnRequest, user *model.User,
	w io.Writer, r *http.Request) error {
	response := i.makeAuthnResponse(authRequest, user)
	// Don't need to change the response. Go ahead and sign it
	signature, err := i.signer.CreateSignature(response.Assertion)
	if err != nil {
		return err
	}
	response.Assertion.Signature = signature
	var xmlbuff bytes.Buffer
	memWriter := bufio.NewWriter(&xmlbuff)
	memWriter.Write([]byte(xml.Header))
	encoder := xml.NewEncoder(memWriter)
	encoder.Encode(response)
	memWriter.Flush()

	samlMessage := base64.StdEncoding.EncodeToString(xmlbuff.Bytes())

	data := struct {
		RelayState                  string
		SAMLResponse                string
		AssertionConsumerServiceURL string
	}{
		authRequest.RelayState,
		samlMessage,
		authRequest.AssertionConsumerServiceURL,
	}
	return i.postTemplate.Execute(w, data)
}

//Assume HTML 5, where <head> is not required
const postTemplate = `<!DOCTYPE html>
<html lang="en">
<body onload="document.getElementById('samlpost').submit()">
<noscript>
<p>
<strong>Note:</strong> Since your browser does not support JavaScript,
you must press the Continue button once to proceed.
</p>
</noscript>
<form action="{{ .AssertionConsumerServiceURL }}" method="post" id="samlpost">
<div>
<input type="hidden" name="RelayState"
value="{{ .RelayState }}"/>
<input type="hidden" name="SAMLResponse"
value="{{ .SAMLResponse }}"/>
</div>
<noscript>
<div>
<input type="submit" value="Continue"/>
</div>
</noscript>
</form>
</body>
</html>`
