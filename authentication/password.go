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
	err := request.ParseForm()
	if err != nil {
		http.Error(writer, err.Error(), 500)
		return
	}
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
	user := &protocol.AuthenticatedUser{uid,
		"urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified",
		"urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport", getIP(request)}
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
	err := storeRequestState(writer, auth.store, authnRequest, relayState)
	if err != nil {
		http.Error(writer, err.Error(), 500)
		return
	}
	// Present the user with the login form
	http.ServeFile(writer, request, auth.form)
}
