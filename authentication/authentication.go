package authentication
import ("net"
    "net/http"
    "strings"
    "crypto/x509/pkix"
    "bytes")

type Authenticator interface {
    Authenticate(*http.Request) (*AuthenticatedUser, error)
}

func NewPKIAuthenticator() Authenticator {
    return &pkiAuthenticator{}
}

type pkiAuthenticator struct {

}

func (_ *pkiAuthenticator) Authenticate(request *http.Request) (*AuthenticatedUser, error) {
    addr := request.RemoteAddr
    if strings.Contains(addr, ":") {
        addr = strings.Split(addr, ":")[0]
    }
    ip := net.ParseIP(addr)
    names := request.TLS.PeerCertificates[0].Subject.Names
    return &AuthenticatedUser{getDN(names),
        "urn:oasis:names:tc:SAML:1.1:nameid-format:X509SubjectName",
        "urn:oasis:names:tc:SAML:2.0:ac:classes:X509", ip}, nil
}

type AuthenticatedUser struct {
    Name string
    Format string
    Context string
    IP net.IP
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