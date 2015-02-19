package authentication
import ("net"
    "net/http"
    "strings")

type Authenticator interface {
    Authenticate(*http.Request) (*AuthenticatedUser, error)
}

func NewDumbAuthenciator() Authenticator {
    return &dumbAuthenciator{}
}

type dumbAuthenciator struct {

}

func (_ *dumbAuthenciator) Authenticate(request *http.Request) (*AuthenticatedUser, error) {
    addr := request.RemoteAddr
    if strings.Contains(addr, ":") {
        addr = strings.Split(addr, ":")[0]
    }
    ip := net.ParseIP(addr)
    return &AuthenticatedUser{"CN=John Doe, OU=IT, O=Some Org, L=Charlottesville, ST=Virginia, C=US",
        "urn:oasis:names:tc:SAML:1.1:nameid-format:X509SubjectName",
        "urn:oasis:names:tc:SAML:2.0:ac:classes:X509", ip}, nil
}

type AuthenticatedUser struct {
    Name string
    Format string
    Context string
    IP net.IP
} 