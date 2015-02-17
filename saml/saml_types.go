package saml
import "encoding/xml"
import "time"
import "net"

type RequestAbstractType struct {
    ID string `xml:",attr"`
    Version string `xml:",attr"`
    IssueInstant string `xml:",attr"`
    Issuer string `xml:"urn:oasis:names:tc:SAML:2.0:assertion Issuer"`
    Destination string `xml:",attr"`
}

type AuthnRequest struct {
    RequestAbstractType
    XMLName xml.Name `xml:"urn:oasis:names:tc:SAML:2.0:protocol AuthnRequest"`
    AssertionConsumerServiceURL string `xml:",attr"`
    ProtocolBinding string `xml:",attr"`
    AttributeConsumingServiceIndex string
    // This doesn't come in the XML but it's convenient to store it here
    RelayState string
}

type ArtifactResolveEnvelope struct {
    XMLName xml.Name `xml:"http://schemas.xmlsoap.org/soap/envelope/ Envelope"`
    Body ArtifactResolveBody
}

type ArtifactResolveBody struct {
    XMLName xml.Name `xml:"http://schemas.xmlsoap.org/soap/envelope/ Body"`
    ArtifactResolve ArtifactResolve
}

type ArtifactResolve struct {
    RequestAbstractType
    XMLName xml.Name `xml:"urn:oasis:names:tc:SAML:2.0:protocol ArtifactResolve"`
    Artifact string `xml:"urn:oasis:names:tc:SAML:2.0:protocol Artifact"`
}

type ArtifactResponseEnvelope struct {
    XMLName xml.Name `xml:"http://schemas.xmlsoap.org/soap/envelope/ Envelope"`
    Body ArtifactResponseBody
}

type ArtifactResponseBody struct {
    XMLName xml.Name `xml:"http://schemas.xmlsoap.org/soap/envelope/ Body"`
    ArtifactResponse ArtifactResponse
}

type ArtifactResponse struct {
    StatusResponseType
    XMLName xml.Name `xml:"urn:oasis:names:tc:SAML:2.0:protocol ArtifactResponse"`
    Response Response
}

type StatusResponseType struct {
    ID string `xml:",attr"`
    Version string `xml:",attr"`
    IssueInstant time.Time `xml:",attr"`
    Issuer *Issuer
    Destination string `xml:",attr,omitempty"`
    InResponseTo string `xml:",attr"`
    Status *Status
}

type Response struct {
    StatusResponseType
    XMLName xml.Name `xml:"urn:oasis:names:tc:SAML:2.0:protocol Response"`
    Assertion *Assertion
}

type Subject struct {
    XMLName xml.Name `xml:"urn:oasis:names:tc:SAML:2.0:assertion Subject"`
    NameID *NameID
    SubjectConfirmation *SubjectConfirmation
}

type Issuer struct {
    XMLName xml.Name `xml:"urn:oasis:names:tc:SAML:2.0:assertion Issuer"`
    Format string `xml:",attr"`
    Value string `xml:",chardata"`
}

type Conditions struct {
    XMLName xml.Name `xml:"urn:oasis:names:tc:SAML:2.0:assertion Conditions"`
    NotBefore time.Time `xml:",attr"`
    NotOnOrAfter time.Time `xml:",attr"`
    AudienceRestriction *AudienceRestriction
}

type SubjectLocality struct {
    XMLName xml.Name `xml:"urn:oasis:names:tc:SAML:2.0:assertion SubjectLocality"`
    Address net.IP `xml:",attr"`
}

type AuthnContext struct {
    XMLName xml.Name `xml:"urn:oasis:names:tc:SAML:2.0:assertion AuthnContext"`
    AuthnContextClassRef string `xml:"urn:oasis:names:tc:SAML:2.0:assertion AuthnContextClassRef"`
}

type AuthnStatement struct {
    XMLName xml.Name `xml:"urn:oasis:names:tc:SAML:2.0:assertion AuthnStatement"`
    AuthnInstant time.Time `xml:",attr"`
    SessionIndex string `xml:",attr"`
    SubjectLocality *SubjectLocality
    AuthnContext *AuthnContext
}

type AttributeValue struct {
    XMLName xml.Name `xml:"urn:oasis:names:tc:SAML:2.0:assertion AttributeValue"`
    Value string `xml:",chardata"`
}

type Attribute struct {
    XMLName xml.Name `xml:"urn:oasis:names:tc:SAML:2.0:assertion Attribute"`
    FriendlyName string `xml:",attr"`
    Name string `xml:",attr"`
    NameFormat string `xml:",attr"`
    AttributeValues []AttributeValue
}

type AttributeStatement struct {
    XMLName xml.Name `xml:"urn:oasis:names:tc:SAML:2.0:assertion AttributeStatement"`
    Attributes []Attribute
}

type NameID struct {
    XMLName xml.Name `xml:"urn:oasis:names:tc:SAML:2.0:assertion NameID"`
    Format string `xml:",attr"`
    NameQualifier string `xml:",attr"`
    SPNameQualifier string `xml:",attr"`
    Value string `xml:",chardata"`
}

type SubjectConfirmation struct {
    XMLName xml.Name `xml:"urn:oasis:names:tc:SAML:2.0:assertion SubjectConfirmation"`
    Method string `xml:",attr"`
    SubjectConfirmationData *SubjectConfirmationData
}

type SubjectConfirmationData struct {
    XMLName xml.Name `xml:"urn:oasis:names:tc:SAML:2.0:assertion SubjectConfirmationData"`
    Address net.IP `xml:",attr"`
    InResponseTo string `xml:",attr"`
    NotOnOrAfter time.Time `xml:",attr"`
    Recipient string `xml:",attr"`
}

type AudienceRestriction struct {
    XMLName xml.Name `xml:"urn:oasis:names:tc:SAML:2.0:assertion AudienceRestriction"`
    Audience string `xml:"urn:oasis:names:tc:SAML:2.0:assertion Audience"`
}

type Assertion struct {
    XMLName xml.Name `xml:"urn:oasis:names:tc:SAML:2.0:assertion Assertion"`
    ID string `xml:",attr"`
    Version string `xml:",attr"`
    IssueInstant time.Time `xml:",attr"`
    Issuer *Issuer
    Subject *Subject
    Conditions *Conditions
    AuthnStatement *AuthnStatement
    AttributeStatement *AttributeStatement
}

type Status struct {
    XMLName xml.Name `xml:"urn:oasis:names:tc:SAML:2.0:protocol Status"`
    StatusCode StatusCode
}
type StatusCode struct {
    XMLName xml.Name `xml:"urn:oasis:names:tc:SAML:2.0:protocol StatusCode"`
    Value string `xml:",attr"`
}












