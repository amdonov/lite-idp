package saml
import (
    "encoding/base64"
    "compress/flate"
    "bytes"
    "encoding/xml")

func ReadRequest(request string) (*AuthnRequest, error) {
    authRequest := &AuthnRequest{}
    // URL decoding will already be done by Go server
    // remove base64 encoding
    reqBytes, err := base64.StdEncoding.DecodeString(request)
    if err!=nil {
        return authRequest, err
    }
    // remove deflate
    req := flate.NewReader(bytes.NewReader(reqBytes))
    // read xml
    decoder := xml.NewDecoder(req)
    decoder.Decode(authRequest)
    return authRequest, nil
}

func NewIssuer(issuer string) *Issuer {
    return &Issuer{Format:"urn:oasis:names:tc:SAML:2.0:nameid-format:entity", Value:issuer}
}

func NewStatus(success bool) *Status {
    s := &Status{}
    if success {
        s.StatusCode = StatusCode{Value:"urn:oasis:names:tc:SAML:2.0:status:Success"}
    }else {
        // TODO figure out Failure /Error status codes boolean isn't sufficient argument
        s.StatusCode = StatusCode{Value:""}
    }
    return s
}

func NewAttributeStatement(attributes map[string][]string) *AttributeStatement {
    stmt := &AttributeStatement{}
    for key, values := range attributes {
        att := Attribute{}
        att.FriendlyName = key
        att.Name = key
        att.NameFormat = "urn:oasis:names:tc:SAML:2.0:attrname-format:basic"
        for index := range values {
            val := AttributeValue{Value:values[index]}
            att.AttributeValues = append(att.AttributeValues, val)
        }
        stmt.Attributes = append(stmt.Attributes, att)
    }
    return stmt
}