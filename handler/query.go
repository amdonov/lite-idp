package handler
import ("github.com/amdonov/xmlsig"
    "github.com/amdonov/lite-idp/attributes"
    "net/http"
    "encoding/xml"
    "github.com/satori/go.uuid"
    "time"
    "github.com/amdonov/lite-idp/saml"
    "github.com/amdonov/lite-idp/protocol")

func NewQueryHandler(signer xmlsig.Signer, retriever attributes.Retriever, entityId string) http.Handler {
    return &queryHandler{signer, retriever, entityId}
}

type queryHandler struct {
    signer xmlsig.Signer
    retriever attributes.Retriever
    entityId string
}

func (handler *queryHandler) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
    decoder := xml.NewDecoder(request.Body)
    var attributeEnv attributes.AttributeQueryEnv
    err := decoder.Decode(&attributeEnv)
    if err!=nil {
        http.Error(writer, err.Error(), 500)
        return
    }
    query := attributeEnv.Body.Query
    name := query.Subject.NameID.Value
    format := query.Subject.NameID.Format
    user := &protocol.AuthenticatedUser{Name:name, Format:format}
    atts, err := handler.retriever.Retrieve(user)
    if err!=nil {
        http.Error(writer, err.Error(), 500)
        return
    }
    var attrResp attributes.AttributeRespEnv
    resp := &attrResp.Body.Response
    resp.ID = uuid.NewV4().String()
    resp.InResponseTo = query.ID
    resp.Version = "2.0"
    now := time.Now()
    resp.IssueInstant = now
    resp.Issuer = saml.NewIssuer(handler.entityId)
    a := &saml.Assertion{}
    a.Issuer = resp.Issuer
    a.IssueInstant = now
    a.ID = uuid.NewV4().String()
    a.Version = "2.0"
    a.Subject = &saml.Subject{}
    a.Subject.NameID = query.Subject.NameID
    a.AttributeStatement = saml.NewAttributeStatement(atts)
    a.Conditions = &saml.Conditions{}
    a.Conditions.NotBefore = now
    fiveMinutes, _ := time.ParseDuration("5m")
    fiveFromNow := now.Add(fiveMinutes)
    a.Conditions.NotOnOrAfter = fiveFromNow
    a.Conditions.AudienceRestriction = &saml.AudienceRestriction{Audience:query.Issuer}
    resp.Status = protocol.NewStatus(true)
    resp.Assertion = a

    signature, err := handler.signer.Sign(a)
    if (err!=nil) {
        http.Error(writer, err.Error(), 500)
        return
    }
    a.Signature = signature

    writer.Write([]byte(xml.Header))
    encoder := xml.NewEncoder(writer)
    encoder.Encode(attrResp)
    encoder.Flush()
}