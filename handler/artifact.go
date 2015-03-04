package handler

import (
	"encoding/xml"
	"fmt"
	"github.com/amdonov/lite-idp/protocol"
	"github.com/amdonov/lite-idp/saml"
	"github.com/amdonov/lite-idp/store"
	"github.com/amdonov/xmlsig"
	"github.com/satori/go.uuid"
	"net/http"
	"time"
)

func NewArtifactHandler(store store.Storer, signer xmlsig.Signer, entityId string) http.Handler {
	return &artifactHandler{store, signer, entityId}
}

type artifactHandler struct {
	store    store.Storer
	signer   xmlsig.Signer
	entityId string
}

func (handler *artifactHandler) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	decoder := xml.NewDecoder(request.Body)
	var resolveEnv protocol.ArtifactResolveEnvelope
	decoder.Decode(&resolveEnv)
	artifact := resolveEnv.Body.ArtifactResolve.Artifact
	var response protocol.Response
	handler.store.Retrieve(artifact, &response)
	artResponseEnv := protocol.ArtifactResponseEnvelope{}
	artResponse := &artResponseEnv.Body.ArtifactResponse
	artResponse.ID = uuid.NewV4().String()
	now := time.Now()
	artResponse.IssueInstant = now
	artResponse.InResponseTo = resolveEnv.Body.ArtifactResolve.ID
	artResponse.Version = "2.0"
	artResponse.Issuer = saml.NewIssuer(handler.entityId)
	artResponse.Status = protocol.NewStatus(true)
	artResponse.Response = response

	signature, err := handler.signer.Sign(response.Assertion)
	if err != nil {
		fmt.Println(err)
	}
	response.Assertion.Signature = signature
	writer.Write([]byte(xml.Header))
	encoder := xml.NewEncoder(writer)
	encoder.Encode(artResponseEnv)
	encoder.Flush()
}
