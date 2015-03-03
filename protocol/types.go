package protocol
import "encoding/xml"
import "time"
import "github.com/amdonov/lite-idp/saml"
import "net"

type AuthenticatedUser struct {
    Name string
    Format string
    Context string
    IP net.IP
}

type AuthnRequest struct {
    RequestAbstractType
    XMLName xml.Name `xml:"urn:oasis:names:tc:SAML:2.0:protocol AuthnRequest"`
    AssertionConsumerServiceURL string `xml:",attr"`
    ProtocolBinding string `xml:",attr"`
    AttributeConsumingServiceIndex string
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

type Response struct {
    StatusResponseType
    XMLName xml.Name `xml:"urn:oasis:names:tc:SAML:2.0:protocol Response"`
    Assertion *saml.Assertion
}

type Status struct {
    XMLName xml.Name `xml:"urn:oasis:names:tc:SAML:2.0:protocol Status"`
    StatusCode StatusCode
}

type StatusCode struct {
    XMLName xml.Name `xml:"urn:oasis:names:tc:SAML:2.0:protocol StatusCode"`
    Value string `xml:",attr"`
}

type RequestAbstractType struct {
    ID string `xml:",attr"`
    Version string `xml:",attr"`
    IssueInstant string `xml:",attr"`
    Issuer string `xml:"urn:oasis:names:tc:SAML:2.0:assertion Issuer"`
    Destination string `xml:",attr"`
}

type StatusResponseType struct {
    ID string `xml:",attr"`
    Version string `xml:",attr"`
    IssueInstant time.Time `xml:",attr"`
    Issuer *saml.Issuer
    Destination string `xml:",attr,omitempty"`
    InResponseTo string `xml:",attr"`
    Status *Status
}

