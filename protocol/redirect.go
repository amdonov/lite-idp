package protocol
import ("net/http"
    "errors"
    "encoding/base64"
    "compress/flate"
    "bytes"
    "encoding/xml")

func NewRedirectRequestParser() RequestParser {
    return &redirectRequestParser{}
}

type redirectRequestParser struct {

}

func (parser *redirectRequestParser) Parse(request *http.Request) (loginReq *AuthnRequest,
relayState string, err error) {
    err = request.ParseForm()
    if err!=nil {
        return
    }
    relayState = request.Form.Get("RelayState")
    if len(relayState)>80 {
        err = errors.New("RelayState cannot be longer than 80 characters.")
        return
    }
    samlReq := request.Form.Get("SAMLRequest")
    // URL decoding is already performed
    // remove base64 encoding
    reqBytes, err := base64.StdEncoding.DecodeString(samlReq)
    if err!=nil {
        return
    }
    // Remove deflate
    req := flate.NewReader(bytes.NewReader(reqBytes))
    // Read the XML
    decoder := xml.NewDecoder(req)
    loginReq = &AuthnRequest{}
    err = decoder.Decode(loginReq)
    return
}
