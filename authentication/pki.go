package authentication
import ("net/http"
    "crypto/x509/pkix"
    "bytes"
    "github.com/amdonov/lite-idp/protocol"
    "github.com/amdonov/lite-idp/store")

func NewPKIAuthenticator(callback AuthFunc, store store.Storer, fallback Authenticator) Authenticator {
    return &pkiAuthenticator{callback, store, fallback}
}

type pkiAuthenticator struct {
    callback AuthFunc
    store store.Storer
    fallback Authenticator
}

func (auth *pkiAuthenticator) Authenticate(authnRequest *protocol.AuthnRequest, relayState string,
writer http.ResponseWriter, request *http.Request) {
    // Does this user have a session?
    user := retrieveUserFromSession(request, auth.store)
    if user==nil {
        // Authenticate the User
        if len(request.TLS.PeerCertificates) == 0 {
            // No certs fallback if available
            if auth.fallback==nil {
                http.Error(writer, "No certificate provided.", 403)
            } else {
                auth.fallback.Authenticate(authnRequest, relayState, writer, request)
            }
            return
        } else {
            names := request.TLS.PeerCertificates[0].Subject.Names
            user = &protocol.AuthenticatedUser{getDN(names),
                "urn:oasis:names:tc:SAML:1.1:nameid-format:X509SubjectName",
                "urn:oasis:names:tc:SAML:2.0:ac:classes:X509", getIP(request)}
            storeUserInSession(writer, auth.store, user)
        }
    }
    auth.callback(authnRequest, relayState, user, writer, request)
}

// Quick attempt at RFC 2253
func getDN(names []pkix.AttributeTypeAndValue) string {
    var buffer bytes.Buffer
    // Reverse the order
    for i := len(names); i>0; i-- {
        t := names[i-1].Type
        if len(t) == 4 && t[0] == 2 && t[1] == 5 && t[2] == 4 {
            switch t[3] {
                case 3:
                buffer.WriteString("CN")
                case 6:
                buffer.WriteString("C")
                case 7:
                buffer.WriteString("L")
                case 8:
                buffer.WriteString("ST")
                case 9:
                buffer.WriteString("STREET")
                case 10:
                buffer.WriteString("O")
                case 11:
                buffer.WriteString("OU")
            }
        }
        buffer.WriteString("=")
        val, _ := names[i-1].Value.(string)
        buffer.WriteString(val)
        if i>1 {
            buffer.WriteString(", ")
        }
    }
    return buffer.String()
}
