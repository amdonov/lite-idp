package protocol

import (
	"net/http"
	"time"

	"github.com/amdonov/lite-idp/saml"
	"github.com/satori/go.uuid"
)

type RequestParser interface {
	Parse(request *http.Request) (*AuthnRequest, string, error)
}

func NewID() string {
	return "_" + uuid.NewV4().String()
}

func NewStatus(success bool) *Status {
	s := &Status{}
	if success {
		s.StatusCode = StatusCode{Value: "urn:oasis:names:tc:SAML:2.0:status:Success"}
	} else {
		// TODO figure out Failure /Error status codes boolean isn't sufficient argument
		s.StatusCode = StatusCode{Value: ""}
	}
	return s
}

type ResponseMarshaller interface {
	Marshal(http.ResponseWriter, *http.Request, *Response, *AuthnRequest, string)
}

type ResponseGenerator interface {
	Generate(*AuthenticatedUser, *AuthnRequest, map[string][]string) *Response
}

func NewDefaultGenerator(entityId string) ResponseGenerator {
	return &defaultGenerator{entityId}
}

type defaultGenerator struct {
	entityId string
}

func (generator *defaultGenerator) Generate(user *AuthenticatedUser, authnRequest *AuthnRequest, attributes map[string][]string) *Response {
	s := &Response{}
	s.Version = "2.0"
	s.ID = NewID()
	now := time.Now()
	fiveMinutes, _ := time.ParseDuration("5m")
	fiveFromNow := now.Add(fiveMinutes)
	fiveBeforeNow := now.Add(-1 * fiveMinutes)
	s.IssueInstant = now
	s.Status = NewStatus(true)
	s.InResponseTo = authnRequest.ID
	s.Issuer = saml.NewIssuer(generator.entityId)
	assertion := &saml.Assertion{}
	assertion.ID = NewID()
	assertion.IssueInstant = now
	assertion.Version = "2.0"
	assertion.Issuer = s.Issuer
	nameId := &saml.NameID{}
	nameId.Format = user.Format
	nameId.NameQualifier = generator.entityId
	nameId.SPNameQualifier = authnRequest.Issuer
	nameId.Value = user.Name
	confirmation := &saml.SubjectConfirmation{}
	confirmation.Method = "urn:oasis:names:tc:SAML:2.0:cm:bearer"
	confData := &saml.SubjectConfirmationData{}
	confData.Address = user.IP
	confData.InResponseTo = authnRequest.ID
	confData.Recipient = authnRequest.AssertionConsumerServiceURL
	confData.NotOnOrAfter = fiveFromNow
	confirmation.SubjectConfirmationData = confData
	subject := &saml.Subject{NameID: nameId, SubjectConfirmation: confirmation}
	assertion.Subject = subject
	conditions := &saml.Conditions{}
	conditions.NotOnOrAfter = fiveFromNow
	conditions.NotBefore = fiveBeforeNow
	audRestriction := &saml.AudienceRestriction{Audience: authnRequest.Issuer}
	conditions.AudienceRestriction = audRestriction
	assertion.Conditions = conditions
	authnStatement := &saml.AuthnStatement{}
	authnStatement.AuthnInstant = now
	authnStatement.SessionIndex = uuid.NewV4().String()
	subLoc := &saml.SubjectLocality{Address: confData.Address}
	authnStatement.SubjectLocality = subLoc
	authContext := &saml.AuthnContext{AuthnContextClassRef: user.Context}
	authnStatement.AuthnContext = authContext
	assertion.AuthnStatement = authnStatement
	assertion.AttributeStatement = saml.NewAttributeStatement(attributes)
	s.Assertion = assertion
	return s
}
