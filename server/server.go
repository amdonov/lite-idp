package server
import ("net/http"
    "github.com/amdonov/xmlsig"
    "crypto/tls"
    "crypto/x509"
    "io/ioutil"
    "os"
    "gopkg.in/redis.v2"
    "github.com/amdonov/lite-idp/attributes"
    "github.com/amdonov/lite-idp/authentication"
    "github.com/amdonov/lite-idp/protocol"
    "github.com/amdonov/lite-idp/handler"
    "log"
    "github.com/amdonov/lite-idp/config")

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
    // Connect to Redis
    client := redis.NewTCPClient(&redis.Options{
        Addr: config.Redis.Address})
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
    marshallers["urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Artifact"] = protocol.NewArtifactResponseMarshaller(client)
    marshallers["urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"] = protocol.NewPOSTResponseMarshaller(signer)
    generator := protocol.NewDefaultGenerator(config.EntityId)
    authHandler := handler.NewAuthenticationHandler(requestParser, authenticator, retriever, generator, marshallers)
    http.Handle(config.Services.Authentication, authHandler)
    queryHandler := handler.NewQueryHandler(signer, retriever, config.EntityId)
    artHandler := handler.NewArtifactHandler(client, signer, config.EntityId)
    http.Handle(config.Services.ArtifactResolution, artHandler)
    http.Handle(config.Services.AttributeQuery, queryHandler)
    metadataHandler, err := handler.NewMetadataHandler(config)
    if err!=nil {
        return nil, err
    }
    http.Handle(config.Services.Metadata, metadataHandler)
    // Set up CAs to verify client certificates
    certs, err := ioutil.ReadFile(config.Authorities)
    if err!=nil {
        return nil, err
    }
    cas := x509.NewCertPool()
    cas.AppendCertsFromPEM(certs)
    tlsConfig := &tls.Config{ClientAuth:tls.RequireAndVerifyClientCert, RootCAs:cas}
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