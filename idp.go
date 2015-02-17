package main

import ("github.com/amdonov/xmlsig"
    "github.com/satori/go.uuid"
    "net/http"
    "crypto/tls"
    "log"
    "github.com/amdonov/idp/saml"
    "text/template"
    "encoding/xml"
    "bytes"
    "encoding/base64"
    "bufio"
    "time"
    "net"
    "os"
    "io")
func main() {
    xmlsig.Initialize()
    defer xmlsig.Terminate()
    cert, err := os.Open("server.crt")
    if err!=nil {
        log.Fatal("Failed to load certificate.", err)
    }
    defer cert.Close()
    key, err := os.Open("server.pem")
    if err!=nil {
        log.Fatal("Failed to load private key..", err)
    }
    sign, err := xmlsig.NewSigner(key, cert)
    http.HandleFunc("/lite-idp/SAML2/Redirect/SSO", getRedirectBinding(sign))
    config := &tls.Config{ClientAuth:tls.RequireAnyClientCert}
    server := http.Server{TLSConfig:config, Addr:":443"}
    if err := server.ListenAndServeTLS("server.crt", "server.pem"); err !=nil {
        log.Fatal("Failed to start server.", err)
    }
}
func getRedirectBinding(signer xmlsig.Signer) func(writer http.ResponseWriter, request *http.Request) {
    return func(writer http.ResponseWriter, request *http.Request) {
        request.ParseForm()
        samlReq := request.Form.Get("SAMLRequest")
        authn, err := saml.ReadRequest(samlReq)
        if err!=nil {
            http.Error(writer, err.Error(), 500)
        }
        authn.RelayState = request.Form.Get("RelayState")
        generatePOSTResponse(writer, authn, signer)
    }
}

func generatePOSTResponse(writer http.ResponseWriter, request *saml.AuthnRequest, signer xmlsig.Signer) error {
    tmpl := template.New("postResponse")
    tmpl.Parse(`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.1//EN"
"http://www.w3.org/TR/xhtml11/DTD/xhtml11.dtd">
<html xmlns="http://www.w3.org/1999/xhtml" xml:lang="en">
<body onload="document.forms[0].submit()">
<noscript>
<p>
<strong>Note:</strong> Since your browser does not support JavaScript,
you must press the Continue button once to proceed.
</p>
</noscript>
<form action="{{ .AssertionConsumerServiceURL }}"
method="post">
<div>
<input type="hidden" name="RelayState"
value="{{ .RelayState }}"/>
<input type="hidden" name="SAMLResponse"
value="{{ .SAMLResponse }}"/>
</div>
<noscript>
<div>
<input type="submit" value="Continue"/>
</div>
</noscript>
</form>
</body>
</html>`)
    samlResp, id := buildSAML(request)
    signed, err := signer.Sign(samlResp, id)
    if (err!=nil) {
        log.Println(err)
    }
    defer signed.Free()
    var buff bytes.Buffer
    memwriter := bufio.NewWriter(&buff)
    io.Copy(memwriter, signed)
    memwriter.Flush()
    samlMessage := base64.StdEncoding.EncodeToString(buff.Bytes())
    response := POSTResponse{request.RelayState, samlMessage, request.AssertionConsumerServiceURL}
    return tmpl.Execute(writer, response)
}

func buildSAML(request *saml.AuthnRequest) (io.Reader, string) {
    s := saml.Response{}
    s.Version = "2.0"
    s.ID = uuid.NewV4().String()
    now := time.Now()
    fiveMinutes, _ := time.ParseDuration("5m")
    fiveFromNow := now.Add(fiveMinutes)
    s.IssueInstant = now
    s.Status = saml.NewStatus(true)
    s.InResponseTo = request.ID
    s.Issuer = saml.NewIssuer("https://idp.example.com/lite-idp/")
    assertion := &saml.Assertion{}
    assertion.ID = uuid.NewV4().String()
    assertion.IssueInstant = now
    assertion.Version = "2.0"
    assertion.Issuer = s.Issuer
    nameId := &saml.NameID{}
    nameId.Format = "urn:oasis:names:tc:SAML:1.1:nameid-format:X509SubjectName"
    nameId.NameQualifier= "https://idp.example.com/lite-idp/"
    nameId.SPNameQualifier = request.Issuer
    nameId.Value = "CN=John Doe, OU=IT, O=Some Org, L=Charlottesville, ST=Virginia, C=US"
    confirmation := &saml.SubjectConfirmation{}
    confirmation.Method = "urn:oasis:names:tc:SAML:2.0:cm:bearer"
    confData := &saml.SubjectConfirmationData{}
    confData.Address = net.ParseIP("172.31.32.91")
    confData.InResponseTo = request.ID
    confData.Recipient = request.AssertionConsumerServiceURL
    confData.NotOnOrAfter = fiveFromNow
    confirmation.SubjectConfirmationData = confData
    subject := &saml.Subject{NameID:nameId, SubjectConfirmation:confirmation}
    assertion.Subject = subject
    conditions := &saml.Conditions{}
    conditions.NotOnOrAfter = fiveFromNow
    conditions.NotBefore = now
    audRestriction := &saml.AudienceRestriction{Audience:request.Issuer}
    conditions.AudienceRestriction = audRestriction
    assertion.Conditions = conditions
    authnStatement := &saml.AuthnStatement{}
    authnStatement.AuthnInstant = now
    authnStatement.SessionIndex = uuid.NewV4().String()
    subLoc := &saml.SubjectLocality{Address:confData.Address}
    authnStatement.SubjectLocality = subLoc
    authContext := &saml.AuthnContext{AuthnContextClassRef:"urn:oasis:names:tc:SAML:2.0:ac:classes:X509"}
    authnStatement.AuthnContext = authContext
    assertion.AuthnStatement = authnStatement

    atts := make(map[string][]string)
    atts["givenName"] = []string{"John"}
    atts["surName"] = []string{"Doe"}
    atts["roles"] = []string{"user", "admin"}
    assertion.AttributeStatement = saml.NewAttributeStatement(atts)
    s.Assertion = assertion

    var buff bytes.Buffer
    writer := bufio.NewWriter(&buff)
    encoder := xml.NewEncoder(writer)
    encoder.Encode(s)
    writer.Flush()
    return bytes.NewReader(buff.Bytes()), assertion.ID
}

type POSTResponse struct {
    RelayState string
    SAMLResponse string
    AssertionConsumerServiceURL string
}