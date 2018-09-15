package idp

import (
	"encoding/xml"
	"net/http"
	"time"

	"github.com/amdonov/lite-idp/model"
	"github.com/amdonov/lite-idp/saml"
	log "github.com/sirupsen/logrus"
)

// DefaultQueryHandler is the default implementation for the attribute query handler. It can be used as is, wrapped in other handlers, or replaced completely.
func (i *IDP) DefaultQueryHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		err := func() error {
			decoder := xml.NewDecoder(r.Body)
			attributeEnv := &saml.AttributeQueryEnv{}
			if err := decoder.Decode(&attributeEnv); err != nil {
				return err
			}
			query := attributeEnv.Body.Query
			user := &model.User{
				Name:   query.Subject.NameID.Value,
				Format: query.Subject.NameID.Format,
			}
			if err := i.setUserAttributes(user); err != nil {
				return err
			}
			response := i.makeResponse(query.ID, query.Issuer, user)
			env := &saml.AttributeRespEnv{
				Body: saml.AttributeRespBody{
					Response: *response,
				},
			}
			var attrResp saml.AttributeRespEnv
			resp := &attrResp.Body.Response
			resp.ID = saml.NewID()
			resp.InResponseTo = query.ID
			resp.Version = "2.0"
			now := time.Now()
			resp.IssueInstant = now
			resp.Issuer = saml.NewIssuer(i.entityID)
			a := &saml.Assertion{}
			a.Issuer = resp.Issuer
			a.IssueInstant = now
			a.ID = saml.NewID()
			a.Version = "2.0"
			a.Subject = &saml.Subject{}
			a.Subject.NameID = query.Subject.NameID
			a.AttributeStatement = user.AttributeStatement()
			a.Conditions = &saml.Conditions{}
			a.Conditions.NotBefore = now
			fiveMinutes, _ := time.ParseDuration("5m")
			fiveFromNow := now.Add(fiveMinutes)
			a.Conditions.NotOnOrAfter = fiveFromNow
			a.Conditions.AudienceRestriction = &saml.AudienceRestriction{Audience: query.Issuer}
			resp.Status = &saml.Status{
				StatusCode: saml.StatusCode{
					Value: "urn:oasis:names:tc:SAML:2.0:status:Success",
				},
			}
			resp.Assertion = a
			signature, err := i.signer.CreateSignature(resp.Assertion)
			// TODO confirm appropriate error response for this service
			if err != nil {
				return err
			}
			resp.Assertion.Signature = signature
			if _, err = w.Write([]byte(xml.Header)); err != nil {
				return err
			}
			encoder := xml.NewEncoder(w)
			if err = encoder.Encode(env); err != nil {
				return err
			}
			return encoder.Flush()
		}()
		if err != nil {
			log.Error(err)
			http.Error(w, err.Error(), http.StatusBadRequest)
		}
	}
}
