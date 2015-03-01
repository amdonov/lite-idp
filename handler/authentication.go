package handler
import ("github.com/amdonov/lite-idp/protocol"
    "github.com/amdonov/lite-idp/authentication"
    "github.com/amdonov/lite-idp/attributes"
    "net/http"
    "github.com/satori/go.uuid"
    "github.com/amdonov/lite-idp/store"
    "log")

func NewAuthenticationHandler(requestParser protocol.RequestParser, authenticator authentication.Authenticator,
retriever attributes.Retriever, generator protocol.ResponseGenerator,
marshallers map[string]protocol.ResponseMarshaller, store store.Storer) http.Handler {
    return &authHandler{requestParser, authenticator, retriever, generator, marshallers, store}
}

type authHandler struct {
    requestParser protocol.RequestParser
    authenticator authentication.Authenticator
    retriever attributes.Retriever
    generator protocol.ResponseGenerator
    marshallers map[string]protocol.ResponseMarshaller
    store store.Storer
}

func (handler *authHandler) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
    // Parse and validate the request
    authRequest, relayState, err := handler.requestParser.Parse(request)
    if err!=nil {
        http.Error(writer, err.Error(), 500)
        return
    }

    var user *authentication.AuthenticatedUser
    // Does this user have a session?
    cookie, err := request.Cookie("lite-idp")
    if err!=nil {
        // Authenticate the User
        user, err = handler.authenticator.Authenticate(request)
        if err!=nil {
            http.Error(writer, err.Error(), 500)
            return
        }
        // Create a session and save user info
        sessionID := uuid.NewV4().String()

        // Save information for 8 hours
        handler.store.Store(sessionID, user, 28800)
        log.Printf("Creating a new session for %s\n", user.Name)

        // Set a cookie for the user session
        c := &http.Cookie{Name:"lite-idp", Value:sessionID, Path:"/", HttpOnly:true, Secure:true}
        http.SetCookie(writer, c)
    } else {
        // Read the user information from Redis
        var tmpUser authentication.AuthenticatedUser
        err := handler.store.Retrieve(cookie.Value, &tmpUser)
        if err!=nil {
            http.Error(writer, err.Error(), 500)
            return
        }
        user = &tmpUser
        log.Printf("Using exising session for %s\n", user.Name)
        // Make sure the IP matches
        if !authentication.GetIP(request).Equal(user.IP) {
            http.Error(writer, "Existing session associated with a different IP address.", 403)
            return
        }
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
