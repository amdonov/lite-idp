package main

import ("github.com/amdonov/xmlsig"
    "github.com/satori/go.uuid"
    "net/http"
    "crypto/tls"
    "log"
    "github.com/amdonov/lite-idp/saml"
    "encoding/xml"
    "bytes"
    "bufio"
    "time"
    "os"
    "io"
    "gopkg.in/redis.v2"
    "github.com/amdonov/lite-idp/protocol"
    "github.com/amdonov/lite-idp/authentication"
    "github.com/amdonov/lite-idp/attributes"
    "encoding/json")
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
        log.Fatal("Failed to load private key.", err)
    }
    signer, err := xmlsig.NewSigner(key, cert)
    entityId := "https://idp.example.com/lite-idp/"
    client := redis.NewTCPClient(&redis.Options{
        Addr: "sp.example.com:6379"})
    handler := &authHandler{}
    handler.authenticator = authentication.NewPKIAuthenticator()
    people, err := os.Open("users.json")
    if err!=nil {
        log.Fatal("Failed to open user file.", err)
    }
    defer people.Close()
    handler.retriever, err = attributes.NewJSONRetriever(people)
    if err!=nil {
        log.Fatal("Failed to read user file.", err)
    }
    handler.requestParser = protocol.NewRedirectRequestParser()
    marshallers := make(map[string]protocol.ResponseMarshaller)
    marshallers["urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Artifact"] = protocol.NewArtifactResponseMarshaller(client)
    marshallers["urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"] = protocol.NewPOSTResponseMarshaller(signer)
    handler.marshallers = marshallers
    handler.generator = protocol.NewDefaultGenerator(entityId)
    http.Handle("/SAML2/Redirect/SSO", handler)

    artHandler := &artifactHandler{client, signer, entityId}
    http.Handle("/SAML2/SOAP/ArtifactResolution", artHandler)
    config := &tls.Config{ClientAuth:tls.RequireAnyClientCert}
    server := http.Server{TLSConfig:config, Addr:":443"}
    if err := server.ListenAndServeTLS("server.crt", "server.pem"); err !=nil {
        log.Fatal("Failed to start server.", err)
    }
}

type authHandler struct {
    requestParser protocol.RequestParser
    authenticator authentication.Authenticator
    retriever attributes.Retriever
    generator protocol.ResponseGenerator
    marshallers map[string]protocol.ResponseMarshaller
}

func (handler *authHandler) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
    // Parse and validate the request
    authRequest, relayState, err := handler.requestParser.Parse(request)
    if err!=nil {
        http.Error(writer, err.Error(), 500)
        return
    }
    // Authenticate the User
    user, err := handler.authenticator.Authenticate(request)
    if err!=nil {
        http.Error(writer, err.Error(), 500)
        return
    }
    // Look up any attributes
    atts, err := handler.retriever.Retrieve(user)
    if err!=nil {
        http.Error(writer, err.Error(), 500)
        return
    }
    // Create a SAML Response
    response := handler.generator.Generate(user, authRequest, atts)
    // Return the response based upon binding
    marshaler, found := handler.marshallers[authRequest.ProtocolBinding]
    if !found {
        http.Error(writer, "Unsupported Binding", 500)
        return
    }
    marshaler.Marshal(writer, request, response, authRequest, relayState)
}

type artifactHandler struct {
    store *redis.Client
    signer xmlsig.Signer
    entityId string
}

func (handler *artifactHandler) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
    decoder := xml.NewDecoder(request.Body)
    var resolveEnv protocol.ArtifactResolveEnvelope
    decoder.Decode(&resolveEnv)
    artifact := resolveEnv.Body.ArtifactResolve.Artifact
    // Fetch the authentication response from Redis
    jsonResponse := handler.store.Get(artifact)
    var response protocol.Response
    err := json.Unmarshal([]byte(jsonResponse.Val()), &response)
    artResponseEnv := protocol.ArtifactResponseEnvelope{}
    artResponse := &artResponseEnv.Body.ArtifactResponse
    artResponse.ID = uuid.NewV4().String()
    now := time.Now()
    artResponse.IssueInstant = now
    artResponse.InResponseTo = resolveEnv.Body.ArtifactResolve.ID
    artResponse.Version="2.0"
    artResponse.Issuer =  saml.NewIssuer(handler.entityId)
    artResponse.Status = protocol.NewStatus(true)
    artResponse.Response = response

    var buff bytes.Buffer
    buffWriter := bufio.NewWriter(&buff)
    encoder := xml.NewEncoder(buffWriter)

    encoder.Encode(artResponseEnv)
    buffWriter.Flush()

    signed, err := handler.signer.Sign(bytes.NewReader(buff.Bytes()), response.Assertion.ID)
    if (err!=nil) {
        log.Println(err)
    }
    defer signed.Free()
    io.Copy(writer, signed)
}
