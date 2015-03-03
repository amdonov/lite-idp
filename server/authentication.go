package server
import ("net/http"
    "github.com/amdonov/lite-idp/protocol"
    "github.com/amdonov/lite-idp/attributes")

type authnresponder struct {
    retriever attributes.Retriever
    generator protocol.ResponseGenerator
    marshallers map[string]protocol.ResponseMarshaller
}

func (responder *authnresponder) completeAuth(authnRequest *protocol.AuthnRequest, relayState string,
user *protocol.AuthenticatedUser,
writer http.ResponseWriter, request *http.Request) {
    // Look up any attributes
    atts, err := responder.retriever.Retrieve(user)
    if err!=nil {
        http.Error(writer, err.Error(), 500)
        return
    }

    // Create a SAML Response
    response := responder.generator.Generate(user, authnRequest, atts)
    // Return the response based upon binding
    marshaler, found := responder.marshallers[authnRequest.ProtocolBinding]
    if !found {
        http.Error(writer, "Unsupported Binding", 500)
        return
    }
    marshaler.Marshal(writer, request, response, authnRequest, relayState)

}
