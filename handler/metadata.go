package handler

import (
	"encoding/base64"
	"encoding/pem"
	"github.com/amdonov/lite-idp/config"
	"io/ioutil"
	"log"
	"net/http"
	"text/template"
)

type metadataHandler struct {
	template      *template.Template
	Configuration *config.Configuration
	Certificate   string
}

func NewMetadataHandler(config *config.Configuration) (http.Handler, error) {
	handler := &metadataHandler{Configuration: config}
	data, err := ioutil.ReadFile(config.Certificate)
	if err != nil {
		return nil, err
	}
	cert, _ := pem.Decode(data)
	handler.Certificate = base64.StdEncoding.EncodeToString(cert.Bytes)
	handler.template = template.New("metadata")
	handler.template.Parse(`<?xml version="1.0" encoding="UTF-8"?>
<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" xmlns:ds="http://www.w3.org/2000/09/xmldsig#"
                  entityID="{{ .Configuration.EntityId }}">
    <IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
        <KeyDescriptor>
            <ds:KeyInfo>
                <ds:X509Data>
                    <ds:X509Certificate>
                        {{ .Certificate }}
                    </ds:X509Certificate>
                </ds:X509Data>
            </ds:KeyInfo>
        </KeyDescriptor>
        <ArtifactResolutionService Binding="urn:oasis:names:tc:SAML:2.0:bindings:SOAP"
                                   Location="{{ .Configuration.BaseURL }}{{ .Configuration.Services.ArtifactResolution }}" index="1"/>
        <NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:X509SubjectName</NameIDFormat>
        <SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
                             Location="{{ .Configuration.BaseURL }}{{ .Configuration.Services.Authentication }}"/>
    </IDPSSODescriptor>
    <AttributeAuthorityDescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
        <KeyDescriptor>
            <ds:KeyInfo>
                <ds:X509Data>
                    <ds:X509Certificate>
                        {{ .Certificate }}
                    </ds:X509Certificate>
                </ds:X509Data>
            </ds:KeyInfo>
        </KeyDescriptor>
        <AttributeService Binding="urn:oasis:names:tc:SAML:2.0:bindings:SOAP"
                          Location="{{ .Configuration.BaseURL }}{{ .Configuration.Services.AttributeQuery }}"/>
        <NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:X509SubjectName</NameIDFormat>
    </AttributeAuthorityDescriptor>
</EntityDescriptor>`)
	return handler, nil
}
func (handler *metadataHandler) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	err := handler.template.Execute(writer, handler)
	if err != nil {
		log.Printf("Failed to render metadata, %s\n", err.Error())
	}
}
