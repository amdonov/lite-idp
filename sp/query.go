package sp

import (
	"bytes"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"

	"github.com/amdonov/lite-idp/saml"
)

func (sp *serviceProvider) Query(nameID string) (*saml.Assertion, error) {
	request, err := sp.buildQueryRequest(nameID)
	if err != nil {
		return nil, err
	}
	post, err := http.NewRequest(http.MethodPost, sp.configuration.IDPQueryEndpoint, request)
	if err != nil {
		return nil, err
	}
	post.Header.Add("Content-Type", "text/xml")
	post.Header.Add("SOAPAction", "http://www.oasis-open.org/committees/security")
	resp, err := sp.client.Do(post)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status code from artifact resolve request %d", resp.StatusCode)
	}
	decoder := xml.NewDecoder(resp.Body)
	response := &saml.AttributeRespEnv{}
	if err := decoder.Decode(response); err != nil {
		return nil, err
	}
	assertion := response.Body.Response.Assertion
	if assertion == nil {
		// TODO check the rest of the response for an error
		// Write it out for now until we know what we're looking
		encoder := xml.NewEncoder(os.Stderr)
		encoder.Encode(response)
		return nil, errors.New("check logs assertion was nil")
	}
	assertion.RawXML = response.Body.Response.RawAssertion
	return assertion, nil
}

func (sp *serviceProvider) buildQueryRequest(nameID string) (io.Reader, error) {
	resolve := saml.AttributeQueryEnv{
		Body: saml.AttributeQueryBody{
			Query: saml.AttributeQuery{
				RequestAbstractType: saml.RequestAbstractType{
					ID:           saml.NewID(),
					IssueInstant: time.Now(),
					Issuer:       sp.configuration.EntityID,
					Version:      "2.0",
				},
				Subject: saml.Subject{
					NameID: &saml.NameID{
						Value:  nameID,
						Format: "urn:oasis:names:tc:SAML:1.1:nameid-format:X509SubjectName",
					},
				},
			},
		},
	}
	signature, err := sp.signer.CreateSignature(resolve.Body.Query)
	if err != nil {
		return nil, err
	}
	resolve.Body.Query.Signature = signature
	var b bytes.Buffer
	encoder := xml.NewEncoder(&b)
	err = encoder.Encode(resolve)
	if err != nil {
		return nil, err
	}
	return bytes.NewReader(b.Bytes()), nil
}
