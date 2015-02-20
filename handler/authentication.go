package handler
import ("github.com/amdonov/lite-idp/protocol"
    "github.com/amdonov/lite-idp/authentication"
    "github.com/amdonov/lite-idp/attributes"
    "net/http")

func NewAuthenticationHandler(requestParser protocol.RequestParser, authenticator authentication.Authenticator,
retriever attributes.Retriever, generator protocol.ResponseGenerator,
marshallers map[string]protocol.ResponseMarshaller) http.Handler {
    return &authHandler{requestParser, authenticator, retriever, generator, marshallers}
}

type authHandler struct {
    requestParser protocol.RequestParser
    authenticator authentication.Authenticator
    retriever attributes.Retriever
    generator protocol.ResponseGenerator
    marshallers map[string]protocol.ResponseMarshaller
}

func (handler *authHandler) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
    // Parse and validate the request
    authRequest, relayState, err := handler.requestParser.Parse(request)
    if err!=nil {
        http.Error(writer, err.Error(), 500)
        return
    }
    // Authenticate the User
    user, err := handler.authenticator.Authenticate(request)
    if err!=nil {
        http.Error(writer, err.Error(), 500)
        return
    }
    // Look up any attributes
    atts, err := handler.retriever.Retrieve(user)
    if err!=nil {
        http.Error(writer, err.Error(), 500)
        return
    }
    // Create a SAML Response
    response := handler.generator.Generate(user, authRequest, atts)
    // Return the response based upon binding
    marshaler, found := handler.marshallers[authRequest.ProtocolBinding]
    if !found {
        http.Error(writer, "Unsupported Binding", 500)
        return
    }
    marshaler.Marshal(writer, request, response, authRequest, relayState)
}
