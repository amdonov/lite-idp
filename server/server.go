package server
import ("net/http"
    "github.com/amdonov/xmlsig"
    "crypto/tls"
    "os"
    "github.com/amdonov/lite-idp/attributes"
    "github.com/amdonov/lite-idp/authentication"
    "github.com/amdonov/lite-idp/protocol"
    "github.com/amdonov/lite-idp/handler"
    "log"
    "github.com/amdonov/lite-idp/config"
    "github.com/amdonov/lite-idp/store")

type IDP interface {
    Start() error
}

type idp struct {
    server *http.Server
    certificate string
    key string
}

func (idp *idp) Start() error {
    return idp.server.ListenAndServeTLS(idp.certificate, idp.key)
}

func New() (IDP, error) {
    // Load configuration data
    config, err := config.LoadConfiguration()
    if err!=nil {
        return nil, err
    }
    // Create a session store
    store := store.New(config.Redis.Address)

    // Configure the XML signer
    signer, err := getSigner(config.Certificate, config.Key)
    if err!=nil {
        return nil, err
    }
    // Load the JSON Attribute Store
    log.Println(config.AttributeProviders.JsonStore.File)
    people, err := os.Open(config.AttributeProviders.JsonStore.File)
    if err!=nil {
        return nil, err
    }
    defer people.Close()
    retriever, err := attributes.NewJSONRetriever(people)
    if err!=nil {
        return nil, err
    }
    authenticator := authentication.NewPKIAuthenticator()
    requestParser := protocol.NewRedirectRequestParser()
    marshallers := make(map[string]protocol.ResponseMarshaller)
    marshallers["urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Artifact"] = protocol.NewArtifactResponseMarshaller(store)
    marshallers["urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"] = protocol.NewPOSTResponseMarshaller(signer)
    generator := protocol.NewDefaultGenerator(config.EntityId)
    authHandler := handler.NewAuthenticationHandler(requestParser, authenticator, retriever, generator,
    marshallers, store)
    http.Handle(config.Services.Authentication, authHandler)
    queryHandler := handler.NewQueryHandler(signer, retriever, config.EntityId)
    artHandler := handler.NewArtifactHandler(store, signer, config.EntityId)
    http.Handle(config.Services.ArtifactResolution, artHandler)
    http.Handle(config.Services.AttributeQuery, queryHandler)
    metadataHandler, err := handler.NewMetadataHandler(config)
    if err!=nil {
        return nil, err
    }
    http.Handle(config.Services.Metadata, metadataHandler)
    tlsConfig := &tls.Config{ClientAuth:tls.RequireAndVerifyClientCert}
    // Start the server
    return &idp{&http.Server{TLSConfig:tlsConfig, Addr:config.Address}, config.Certificate, config.Key }, nil
}

func getSigner(certPath string, keyPath string) (xmlsig.Signer, error) {
    cert, err := os.Open(certPath)
    if err!=nil {
        return nil, err
    }
    defer cert.Close()
    key, err := os.Open(keyPath)
    if err!=nil {
        return nil, err
    }
    return xmlsig.NewSigner(key, cert)
}