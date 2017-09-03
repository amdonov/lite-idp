package authentication

import (
	"crypto/x509/pkix"
	"fmt"
	"net/http"
	"strings"

	"github.com/amdonov/lite-idp/protocol"
	"github.com/amdonov/lite-idp/store"
)

func NewPKIAuthenticator(callback AuthFunc, store store.Storer, fallback Authenticator) Authenticator {
	return &pkiAuthenticator{callback, store, fallback}
}

type pkiAuthenticator struct {
	callback AuthFunc
	store    store.Storer
	fallback Authenticator
}

func (auth *pkiAuthenticator) Authenticate(authnRequest *protocol.AuthnRequest, relayState string,
	writer http.ResponseWriter, request *http.Request) {
	// Does this user have a session?
	user := retrieveUserFromSession(request, auth.store)
	if user == nil {
		// Authenticate the User
		if len(request.TLS.PeerCertificates) == 0 {
			// No certs fallback if available
			if auth.fallback == nil {
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

// GetSubjectDN is a quick attempt at RFC 2253.
func GetSubjectDN(subject pkix.Name) string {
	rdns := []string{}
	names := subject.Names
	// Reverse the order
	for i := len(names) - 1; i >= 0; i-- {
		t := names[i].Type
		if len(t) == 4 && t[0] == 2 && t[1] == 5 && t[2] == 4 {
			var rdnName string
			switch t[3] {
			case 3:
				rdnName = "CN"
			case 6:
				rdnName = "C"
			case 7:
				rdnName = "L"
			case 8:
				rdnName = "ST"
			case 9:
				rdnName = "STREET"
			case 10:
				rdnName = "O"
			case 11:
				rdnName = "OU"
			default:
				panic("RFC 2253 implementation is incomplete")
			}
			rdnValue, _ := names[i].Value.(string)
			rdns = append(rdns, fmt.Sprintf("%s=%s", rdnName, rdnValue))
		}
	}
	return strings.Join(rdns, ", ")
}
