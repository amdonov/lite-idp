package main

import ("github.com/amdonov/xmlsig"
    "github.com/satori/go.uuid"
    "net/http"
    "crypto/tls"
    "log"
    "github.com/amdonov/lite-idp/saml"
    "text/template"
    "encoding/xml"
    "bytes"
    "encoding/base64"
    "bufio"
    "time"
    "net"
    "os"
    "io"
    "net/url"
    "crypto/sha1")
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
    signer, err := xmlsig.NewSigner(key, cert)
    http.HandleFunc("/SAML2/Redirect/SSO", getRedirectBinding(signer))
    http.HandleFunc("/SAML2/SOAP/ArtifactResolution", getArtifactBinding(signer))
    config := &tls.Config{ClientAuth:tls.RequireAnyClientCert}
    server := http.Server{TLSConfig:config, Addr:":443"}
    if err := server.ListenAndServeTLS("server.crt", "server.pem"); err !=nil {
        log.Fatal("Failed to start server.", err)
    }
}
func getArtifactBinding(signer xmlsig.Signer) func(writer http.ResponseWriter, request *http.Request) {
    return func(writer http.ResponseWriter, request *http.Request) {
        // retrieve ID and artifact from the request to prepare the response
        decoder := xml.NewDecoder(request.Body)
        var resolveEnv saml.ArtifactResolveEnvelope
        decoder.Decode(&resolveEnv)
        //  encoder := xml.NewEncoder(writer)
        artResponseEnv := saml.ArtifactResponseEnvelope{}
        artResponse := &artResponseEnv.Body.ArtifactResponse
        artResponse.ID = uuid.NewV4().String()
        now := time.Now()
        fiveMinutes, _ := time.ParseDuration("5m")
        fiveFromNow := now.Add(fiveMinutes)
        artResponse.IssueInstant = now
        artResponse.InResponseTo = resolveEnv.Body.ArtifactResolve.ID
        artResponse.Version="2.0"
        artResponse.Issuer =  saml.NewIssuer("https://idp.example.com/lite-idp/")
        artResponse.Status = saml.NewStatus(true)
        sResponse := &artResponse.Response
        sResponse.Version="2.0"
        sResponse.IssueInstant=now
        sResponse.InResponseTo = uuid.NewV4().String()
        sResponse.ID = uuid.NewV4().String()
        sResponse.Issuer =  saml.NewIssuer("https://idp.example.com/lite-idp/")
        sResponse.Status = saml.NewStatus(true)
        assertion := &saml.Assertion{}
        sResponse.Assertion=assertion
        assertion.IssueInstant = now
        assertion.Version="2.0"
        assertion.ID= uuid.NewV4().String()
        assertion.Issuer =  saml.NewIssuer("https://idp.example.com/lite-idp/")

        nameId := &saml.NameID{}
        nameId.Format = "urn:oasis:names:tc:SAML:1.1:nameid-format:X509SubjectName"
        nameId.NameQualifier= "https://idp.example.com/lite-idp/"
        nameId.SPNameQualifier = "https://idp.example.com/lite-idp/"
        nameId.Value = "CN=John Doe, OU=IT, O=Some Org, L=Charlottesville, ST=Virginia, C=US"
        confirmation := &saml.SubjectConfirmation{}
        confirmation.Method = "urn:oasis:names:tc:SAML:2.0:cm:bearer"
        confData := &saml.SubjectConfirmationData{}
        confData.Address = net.ParseIP("172.31.32.91")
        confData.InResponseTo = resolveEnv.Body.ArtifactResolve.ID
        confData.Recipient = "https://sp.example.com/Shibboleth.sso/SAML2/Artifact"
        confData.NotOnOrAfter = fiveFromNow
        confirmation.SubjectConfirmationData = confData
        subject := &saml.Subject{NameID:nameId, SubjectConfirmation:confirmation}
        assertion.Subject = subject
        conditions := &saml.Conditions{}
        conditions.NotOnOrAfter = fiveFromNow
        conditions.NotBefore = now
        audRestriction := &saml.AudienceRestriction{Audience:resolveEnv.Body.ArtifactResolve.Issuer}
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


        var buff bytes.Buffer
        buffWriter := bufio.NewWriter(&buff)
        encoder := xml.NewEncoder(buffWriter)

        encoder.Encode(artResponseEnv)
        buffWriter.Flush()

        signed, err := signer.Sign(bytes.NewReader(buff.Bytes()), assertion.ID)
        if (err!=nil) {
            log.Println(err)
        }
        defer signed.Free()
        io.Copy(writer, signed)
    }
}

func getRedirectBinding(signer xmlsig.Signer) func(writer http.ResponseWriter, request *http.Request) {
    return func(writer http.ResponseWriter, request *http.Request) {
        request.ParseForm()
        samlReq := request.Form.Get("SAMLRequest")
        authn, err := saml.ReadRequest(samlReq)
        if err!=nil {
            http.Error(writer, err.Error(), 500)
            return
        }
        authn.RelayState = request.Form.Get("RelayState")
        switch authn.ProtocolBinding {
            case "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Artifact":generateArtifactResponse(writer, request, authn)
            case "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST":generatePOSTResponse(writer, authn, signer)
            default: http.Error(writer, "Unsupported binding.", 500)
        }
    }
}

func getArtifact() string {
    // The artifact isn't just a random session id. It's a base64-encoded byte array
    // that's 44 bytes in length. The first two bytes must be 04 for SAML 2. The second
    // two bytes are the index of the artifact resolution endpoint in the IdP metadata. Something like 02
    // The next 20 bytes are the sha1 hash of the IdP's entity ID
    // The last 20 bytes are unique to the request
    artifact := make([]byte, 44)
    // Use SAML 2
    artifact[1] = byte(4)
    // Index 2
    artifact[3] = byte(2)
    // Hash of entity ID
    source := sha1.Sum([]byte("https://idp.example.com/lite-idp/"))
    for i := 4; i < 24; i++ {
        artifact[i] = source[i-4]
    }
    // Message ID
    message := sha1.Sum(uuid.NewV4().Bytes())
    for i := 24; i < 44; i++ {
        artifact[i] = message[i-24]
    }
    return base64.StdEncoding.EncodeToString(artifact)
}

func generateArtifactResponse(writer http.ResponseWriter, request *http.Request, authRequest *saml.AuthnRequest) {
    target, err := url.Parse(authRequest.AssertionConsumerServiceURL)
    if err!=nil {
        http.Error(writer, err.Error(), 500)
    }
    parameters := url.Values{}
    parameters.Add("SAMLart", getArtifact())
    parameters.Add("RelayState", authRequest.RelayState)
    target.RawQuery = parameters.Encode()
    http.Redirect(writer, request, target.String(), 302)
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