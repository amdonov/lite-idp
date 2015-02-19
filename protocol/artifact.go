package protocol
import ("crypto/sha1"
    "github.com/satori/go.uuid"
    "encoding/base64"
    "net/http"
    "net/url"
    "gopkg.in/redis.v2"
    "time"
    "encoding/json")

func NewArtifactResponseMarshaller(client *redis.Client) ResponseMarshaller {
    return &artifactResponseMarshaller{client}
}

type artifactResponseMarshaller struct {
    client *redis.Client
}

func (gen *artifactResponseMarshaller) Marshal(writer http.ResponseWriter, request *http.Request, response *Response, authRequest *AuthnRequest, relayState string) {
    target, err := url.Parse(authRequest.AssertionConsumerServiceURL)
    if err!=nil {
        http.Error(writer, err.Error(), 500)
    }
    parameters := url.Values{}
    // Save the response to Redis
    artifact := getArtifact(response.Issuer.Value)
    jsonResp, _ := json.Marshal(response)
    dur, _ := time.ParseDuration("5m")
    gen.client.SetEx(artifact, dur, string(jsonResp))
    parameters.Add("SAMLart", artifact)
    parameters.Add("RelayState", relayState)
    target.RawQuery = parameters.Encode()
    http.Redirect(writer, request, target.String(), 302)
}

func getArtifact(entityId string) string {
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
    source := sha1.Sum([]byte(entityId))
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
