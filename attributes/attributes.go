package attributes
import "github.com/amdonov/lite-idp/authentication"

type Retriever interface {
    Retrieve(*authentication.AuthenticatedUser) (map[string][]string, error)
}

func NewDumbRetriver() Retriever {
    return &dumbRetriever{}
}

type dumbRetriever struct {

}

func (_ *dumbRetriever) Retrieve(user *authentication.AuthenticatedUser) (map[string][]string, error) {
    atts := make(map[string][]string)
    atts["givenName"] = []string{"John"}
    atts["surName"] = []string{"Doe"}
    atts["roles"] = []string{"user", "admin"}
    return atts, nil
}