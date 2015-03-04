package protocol

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"encoding/xml"
	"github.com/amdonov/xmlsig"
	"log"
	"net/http"
	"text/template"
)

func NewPOSTResponseMarshaller(signer xmlsig.Signer) ResponseMarshaller {
	generator := &postResponseMarshaller{signer: signer}
	generator.template = template.New("postResponse")
	generator.template.Parse(`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.1//EN"
"http://www.w3.org/TR/xhtml11/DTD/xhtml11.dtd">
<html xmlns="http://www.w3.org/1999/xhtml" xml:lang="en">
<body onload="document.forms[0].submit()">
<noscript>
<p>
<strong>Note:</strong> Since your browser does not support JavaScript,
you must press the Continue button once to proceed.
</p>
</noscript>
<form action="{{ .AssertionConsumerServiceURL }}"
method="post">
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
</html>`)
	return generator
}

type postResponseMarshaller struct {
	template *template.Template
	signer   xmlsig.Signer
}

func (gen *postResponseMarshaller) Marshal(writer http.ResponseWriter, request *http.Request,
	response *Response, authRequest *AuthnRequest, relayState string) {
	// Don't need to change the response. Go ahead and sign it
	signature, err := gen.signer.Sign(response.Assertion)
	if err != nil {
		log.Println(err)
		return
	}
	response.Assertion.Signature = signature
	var xmlbuff bytes.Buffer
	memWriter := bufio.NewWriter(&xmlbuff)
	memWriter.Write([]byte(xml.Header))
	encoder := xml.NewEncoder(memWriter)
	encoder.Encode(response)
	memWriter.Flush()

	samlMessage := base64.StdEncoding.EncodeToString(xmlbuff.Bytes())
	postResponse := POSTResponse{relayState, samlMessage, authRequest.AssertionConsumerServiceURL}
	gen.template.Execute(writer, postResponse)
}

type POSTResponse struct {
	RelayState                  string
	SAMLResponse                string
	AssertionConsumerServiceURL string
}
