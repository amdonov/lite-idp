package authentication
import ("net"
    "net/http"
    "strings"
    "github.com/amdonov/lite-idp/protocol"
    "github.com/amdonov/lite-idp/store"
    "log"
    "github.com/satori/go.uuid")

type AuthFunc func(*protocol.AuthnRequest, string, *protocol.AuthenticatedUser, http.ResponseWriter, *http.Request)

type Authenticator interface {
    Authenticate(*protocol.AuthnRequest, string, http.ResponseWriter, *http.Request)
}

type HandlerAuthenticator interface {
    http.Handler
    Authenticator
}

func getIP(request *http.Request) net.IP {
    addr := request.RemoteAddr
    if strings.Contains(addr, ":") {
        addr = strings.Split(addr, ":")[0]
    }
    return net.ParseIP(addr)
}

func retrieveUserFromSession(request *http.Request, store store.Storer) *protocol.AuthenticatedUser {
    // Does this user have a session?
    cookie, err := request.Cookie("lidp-user")
    if err!=nil {
        return nil
    }
    // Read the user information from Redis
    var tmpUser protocol.AuthenticatedUser
    err = store.Retrieve(cookie.Value, &tmpUser)
    if err!=nil {
        return nil
    }
    user := &tmpUser
    log.Printf("Using exising session for %s\n", user.Name)
    // Make sure the IP matches
    if !getIP(request).Equal(user.IP) {
        log.Println("Warning - Existing session associated with a different IP address.")
        // Force them to authenticate again
        return nil
    }
    return user
}

func storeUserInSession(writer http.ResponseWriter, store store.Storer, user *protocol.AuthenticatedUser) {
    // Create a session and save user info
    sessionID := uuid.NewV4().String()

    // Set a cookie for the user session
    c := &http.Cookie{Name:"lidp-user", Value:sessionID, Path:"/", HttpOnly:true, Secure:true}
    http.SetCookie(writer, c)

    // Save information for 8 hours
    store.Store(sessionID, user, 28800)
    log.Printf("Creating a new session for %s\n", user.Name)

}

type RequestState struct {
    AuthnRequest *protocol.AuthnRequest
    RelayState string
}

func storeRequestState(writer http.ResponseWriter, store store.Storer, authnRequest *protocol.AuthnRequest, relayState string) {
    // Save the request and relaystate for 5 minutes
    sessionID := uuid.NewV4().String()
    state := RequestState{authnRequest, relayState}
    store.Store(sessionID, state, 300)
    // Set a cookie for the request state
    c := &http.Cookie{Name:"lidp-rs", Value:sessionID, Path:"/", HttpOnly:true, Secure:true}
    http.SetCookie(writer, c)
}

func retrieveRequestState(request *http.Request, store store.Storer) (*protocol.AuthnRequest, string) {
    // Does this user have a saved request state
    cookie, err := request.Cookie("lidp-rs")
    if err!=nil {
        return nil, ""
    }
    // Read the user information from Redis
    var rs RequestState
    err = store.Retrieve(cookie.Value, &rs)
    if err!=nil {
        log.Println(err)
        return nil, ""
    }
    log.Printf("Should have a good result - %s", rs.RelayState)
    return rs.AuthnRequest, rs.RelayState

}