package handler
import ("github.com/amdonov/lite-idp/protocol"
    "github.com/amdonov/lite-idp/authentication"
    "net/http")

func NewAuthenticationHandler(requestParser protocol.RequestParser, authenticator authentication.Authenticator) http.Handler {
    return &authHandler{requestParser, authenticator}
}

type authHandler struct {
    requestParser protocol.RequestParser
    authenticator authentication.Authenticator
}

func (handler *authHandler) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
    // Parse and validate the request
    authRequest, relayState, err := handler.requestParser.Parse(request)
    if err!=nil {
        http.Error(writer, err.Error(), 500)
        return
    }

    handler.authenticator.Authenticate(authRequest, relayState, writer, request)
}
