package attributes
import "encoding/xml"
import "github.com/amdonov/lite-idp/saml"
import "github.com/amdonov/lite-idp/protocol"

type AttributeQueryEnv struct {
    XMLName xml.Name `xml:"http://schemas.xmlsoap.org/soap/envelope/ Envelope"`
    Body AttributeQueryBody
}

type AttributeQueryBody struct {
    XMLName xml.Name `xml:"http://schemas.xmlsoap.org/soap/envelope/ Body"`
    Query AttributeQuery
}

type AttributeQuery struct {
    XMLName xml.Name `xml:"urn:oasis:names:tc:SAML:2.0:protocol AttributeQuery"`
    ID string `xml:",attr"`
    Issuer string `xml:"urn:oasis:names:tc:SAML:2.0:assertion Issuer"`
    Subject saml.Subject
}

type AttributeRespEnv struct {
    XMLName xml.Name `xml:"http://schemas.xmlsoap.org/soap/envelope/ Envelope"`
    Body AttributeRespBody
}

type AttributeRespBody struct {
    XMLName xml.Name `xml:"http://schemas.xmlsoap.org/soap/envelope/ Body"`
    Response protocol.Response
}

