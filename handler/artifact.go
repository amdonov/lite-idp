package handler
import ("gopkg.in/redis.v2"
    "github.com/amdonov/xmlsig"
    "net/http"
    "encoding/xml"
    "github.com/amdonov/lite-idp/protocol"
    "encoding/json"
    "github.com/satori/go.uuid"
    "time"
    "github.com/amdonov/lite-idp/saml"
    "fmt")

func NewArtifactHandler(store *redis.Client, signer xmlsig.Signer, entityId string) http.Handler {
    return &artifactHandler{store, signer, entityId}
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

    signature, err := handler.signer.Sign(response.Assertion)
    if err!=nil {
        fmt.Println(err)
    }
    response.Assertion.Signature = signature
    encoder := xml.NewEncoder(writer)
    encoder.Encode(artResponseEnv)
    encoder.Flush()
}

