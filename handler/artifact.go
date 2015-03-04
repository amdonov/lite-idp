package handler

import (
	"encoding/xml"
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
	err := decoder.Decode(&resolveEnv)
	// TODO confirm appropriate error response for this service
	if err != nil {
		http.Error(writer, err.Error(), 500)
		return
	}
	// TODO validate resolveEnv before proceeding
	artifact := resolveEnv.Body.ArtifactResolve.Artifact
	var response protocol.Response
	err = handler.store.Retrieve(artifact, &response)
	// TODO confirm appropriate error response for this service
	if err != nil {
		http.Error(writer, err.Error(), 500)
		return
	}
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
	// TODO confirm appropriate error response for this service
	if err != nil {
		http.Error(writer, err.Error(), 500)
		return
	}
	response.Assertion.Signature = signature
	// TODO handle these errors. Probably can't do anything besides log, as we've already started to write the
	// response.
	err = writer.Write([]byte(xml.Header))
	encoder := xml.NewEncoder(writer)
	err = encoder.Encode(artResponseEnv)
	err = encoder.Flush()
}
