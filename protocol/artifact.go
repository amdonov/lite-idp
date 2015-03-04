package protocol

import (
	"crypto/sha1"
	"encoding/base64"
	"github.com/amdonov/lite-idp/store"
	"github.com/satori/go.uuid"
	"net/http"
	"net/url"
)

func NewArtifactResponseMarshaller(store store.Storer) ResponseMarshaller {
	return &artifactResponseMarshaller{store}
}

type artifactResponseMarshaller struct {
	store store.Storer
}

func (gen *artifactResponseMarshaller) Marshal(writer http.ResponseWriter, request *http.Request, response *Response, authRequest *AuthnRequest, relayState string) {
	target, err := url.Parse(authRequest.AssertionConsumerServiceURL)
	if err != nil {
		http.Error(writer, err.Error(), 500)
	}
	parameters := url.Values{}
	// Save the response to Redis
	artifact := getArtifact(response.Issuer.Value)
	// Store the artifact for 5 minutes
	gen.store.Store(artifact, response, 300)
	parameters.Add("SAMLart", artifact)
	parameters.Add("RelayState", relayState)
	target.RawQuery = parameters.Encode()
	http.Redirect(writer, request, target.String(), 302)
}

func getArtifact(entityId string) string {
	// The artifact isn't just a random session id. It's a base64-encoded byte array
	// that's 44 bytes in length. The first two bytes must be 04 for SAML 2. The second
	// two bytes are the index of the artifact resolution endpoint in the IdP metadata. Something like 02
	// The next 20 bytes are the sha1 hash of the IdP's entity ID
	// The last 20 bytes are unique to the request
	artifact := make([]byte, 44)
	// Use SAML 2
	artifact[1] = byte(4)
	// Index 1
	artifact[3] = byte(1)
	// Hash of entity ID
	source := sha1.Sum([]byte(entityId))
	for i := 4; i < 24; i++ {
		artifact[i] = source[i-4]
	}
	// Message ID
	message := sha1.Sum(uuid.NewV4().Bytes())
	for i := 24; i < 44; i++ {
		artifact[i] = message[i-24]
	}
	return base64.StdEncoding.EncodeToString(artifact)
}
