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
			if err := i.setUserAttributes(user, nil); err != nil {
				return err
			}
			response := i.makeResponse(query.ID, query.Issuer, user)
			env := &saml.AttributeRespEnv{
				Body: saml.AttributeRespBody{
					Response: *response,
				},
			}
			now := time.Now().UTC()
			fiveMinutes, _ := time.ParseDuration("5m")
			fiveFromNow := now.Add(fiveMinutes)
			attrResp := &saml.AttributeRespEnv{
				Body: saml.AttributeRespBody{
					Response: saml.Response{
						StatusResponseType: saml.StatusResponseType{
							Version:      "2.0",
							ID:           saml.NewID(),
							IssueInstant: now,
							Status: &saml.Status{
								StatusCode: saml.StatusCode{
									Value: "urn:oasis:names:tc:SAML:2.0:status:Success",
								},
							},
							InResponseTo: query.ID,
							Issuer:       saml.NewIssuer(i.entityID),
						},
						Assertion: &saml.Assertion{
							Issuer:       saml.NewIssuer(i.entityID),
							IssueInstant: now,
							ID:           saml.NewID(),
							Version:      "2.0",
							Subject: &saml.Subject{
								NameID: query.Subject.NameID,
							},
							AttributeStatement: user.AttributeStatement(),
							Conditions: &saml.Conditions{
								NotBefore:           now,
								NotOnOrAfter:        fiveFromNow,
								AudienceRestriction: &saml.AudienceRestriction{Audience: query.Issuer},
							},
						},
					},
				},
			}
			resp := attrResp.Body.Response
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
			i.Error(w, err.Error(), http.StatusBadRequest)
		}
	}
}
