package saml

import (
	"encoding/xml"

	"github.com/amdonov/xmlsig"
)

type AttributeQueryEnv struct {
	XMLName xml.Name `xml:"http://schemas.xmlsoap.org/soap/envelope/ Envelope"`
	Body    AttributeQueryBody
}

type AttributeQueryBody struct {
	XMLName xml.Name `xml:"http://schemas.xmlsoap.org/soap/envelope/ Body"`
	Query   AttributeQuery
}

type AttributeQuery struct {
	RequestAbstractType
	XMLName   xml.Name `xml:"urn:oasis:names:tc:SAML:2.0:protocol AttributeQuery"`
	Subject   Subject
	Signature *xmlsig.Signature
}

type AttributeRespEnv struct {
	XMLName xml.Name `xml:"http://schemas.xmlsoap.org/soap/envelope/ Envelope"`
	Body    AttributeRespBody
}

type AttributeRespBody struct {
	XMLName  xml.Name `xml:"http://schemas.xmlsoap.org/soap/envelope/ Body"`
	Response Response
}
