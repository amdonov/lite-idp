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
    "bytes"
    "bufio"
    "log"
    "io")

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

