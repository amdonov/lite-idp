package main

import ("github.com/amdonov/xmlsig"
    "net/http"
    "crypto/tls"
    "log"
    "os"
    "gopkg.in/redis.v2"
    "github.com/amdonov/lite-idp/protocol"
    "github.com/amdonov/lite-idp/authentication"
    "github.com/amdonov/lite-idp/attributes"
    "github.com/amdonov/lite-idp/handler")
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
    people, err := os.Open("users.json")
    if err!=nil {
        log.Fatal("Failed to open user file.", err)
    }
    defer people.Close()
    retriever, err := attributes.NewJSONRetriever(people)
    if err!=nil {
        log.Fatal("Failed to read user file.", err)
    }
    authenticator := authentication.NewPKIAuthenticator()
    requestParser := protocol.NewRedirectRequestParser()
    marshallers := make(map[string]protocol.ResponseMarshaller)
    marshallers["urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Artifact"] = protocol.NewArtifactResponseMarshaller(client)
    marshallers["urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"] = protocol.NewPOSTResponseMarshaller(signer)
    generator := protocol.NewDefaultGenerator(entityId)
    authHandler := handler.NewAuthenticationHandler(requestParser, authenticator, retriever, generator, marshallers)
    http.Handle("/SAML2/Redirect/SSO", authHandler)
    queryHandler := handler.NewQueryHandler(signer, retriever, entityId)
    artHandler := handler.NewArtifactHandler(client, signer, entityId)
    http.Handle("/SAML2/SOAP/ArtifactResolution", artHandler)
    http.Handle("/SAML2/SOAP/AttributeQuery", queryHandler)
    config := &tls.Config{ClientAuth:tls.RequireAnyClientCert}
    server := http.Server{TLSConfig:config, Addr:":443"}
    if err := server.ListenAndServeTLS("server.crt", "server.pem"); err !=nil {
        log.Fatal("Failed to start server.", err)
    }
}

