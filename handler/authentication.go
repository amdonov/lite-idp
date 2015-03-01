package handler
import ("github.com/amdonov/lite-idp/protocol"
    "github.com/amdonov/lite-idp/authentication"
    "github.com/amdonov/lite-idp/attributes"
    "net/http"
    "log"
    "github.com/satori/go.uuid")

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

    // Does this user have a session?
    cookie, err := request.Cookie("lite-idp")
    if err!=nil {
        // Authenticate the user

        // Create a session and save user info
        sessionID := uuid.NewV4().String()

        // Set a cookie for the user session
        c := &http.Cookie{Name:"lite-idp", Value:sessionID, Path:"/", HttpOnly:true, Secure:true}
        http.SetCookie(writer, c)
    } else {
        // Read the user information from Redis
        log.Printf("User already has a session, %s\n", cookie.Value)

    }
    // Authenticate the User
    user, err := handler.authenticator.Authenticate(request)
    if err!=nil {
        http.Error(writer, err.Error(), 500)
        return
    }
    
    // Attributes aren't directly associated with user session
    // A poorly behaving client that doesn't maintain cookies could
    // create many sessions and consume a great deal of memory
    
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
