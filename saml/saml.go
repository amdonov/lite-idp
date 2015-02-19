package saml

func NewIssuer(issuer string) *Issuer {
    return &Issuer{Format:"urn:oasis:names:tc:SAML:2.0:nameid-format:entity", Value:issuer}
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
