package authentication

import (
	"github.com/amdonov/lite-idp/config"
	"github.com/amdonov/lite-idp/protocol"
	"github.com/amdonov/lite-idp/store"
	"net/http"
)

func NewPasswordAuthenticator(callback AuthFunc, store store.Storer, form *config.Form) HandlerAuthenticator {
	return &passwordAuthenticator{callback, store, form.Form, form.Error}
}

type passwordAuthenticator struct {
	callback  AuthFunc
	store     store.Storer
	form      string
	errorPage string
}

func (auth *passwordAuthenticator) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	request.ParseForm()
	uid := request.Form.Get("uid")
	pwd := request.Form.Get("pwd")
	if "jdoe" != uid && "secret" != pwd {
		http.ServeFile(writer, request, auth.errorPage)
		return
	}
	authnRequest, relayState := retrieveRequestState(request, auth.store)
	if authnRequest == nil {
		http.Error(writer, "Failed to restore your request. Perhaps authentication took too long or you are not accepting cookies.", 500)
		return
	}
	// TODO these values aren't correct for password authentication
	user := &protocol.AuthenticatedUser{"CN=John Doe, OU=sample, O=lite idp, L=Charlottesville, ST=Virginia, C=US",
		"urn:oasis:names:tc:SAML:1.1:nameid-format:X509SubjectName",
		"urn:oasis:names:tc:SAML:2.0:ac:classes:X509", getIP(request)}
	storeUserInSession(writer, auth.store, user)
	auth.callback(authnRequest, relayState, user, writer, request)
}

func (auth *passwordAuthenticator) Authenticate(authnRequest *protocol.AuthnRequest, relayState string,
	writer http.ResponseWriter, request *http.Request) {
	// Does this user have a session?
	user := retrieveUserFromSession(request, auth.store)
	if user != nil {
		// We're good no need to have them login again
		auth.callback(authnRequest, relayState, user, writer, request)
		return
	}
	storeRequestState(writer, auth.store, authnRequest, relayState)
	// Present the user with the login form
	http.ServeFile(writer, request, auth.form)
	return
}
