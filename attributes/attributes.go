package attributes
import "github.com/amdonov/lite-idp/protocol"
import "io"
import "errors"
import "encoding/json"

type Retriever interface {
    Retrieve(*protocol.AuthenticatedUser) (map[string][]string, error)
}

func NewJSONRetriever(jsonData io.Reader) (Retriever, error) {
    var people map[string]map[string][]string
    decoder := json.NewDecoder(jsonData)
    err := decoder.Decode(&people)
    if err!=nil {
        return nil, err
    }
    return &jsonRetriever{people}, nil
}

type jsonRetriever struct {
    people map[string]map[string][]string
}

func (store *jsonRetriever) Retrieve(user *protocol.AuthenticatedUser) (map[string][]string, error) {
    attributes, found := store.people[user.Name]
    if !found {
        return nil, errors.New("No attributes found for "+user.Name)
    }
    return attributes, nil
}