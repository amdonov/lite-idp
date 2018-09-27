package saml

import (
	"bytes"
	"encoding/xml"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

// This is to test that RawXML doesn't end up in SAML Assertions. It was happening
func TestRawXML(t *testing.T) {
	var b bytes.Buffer
	assertion := Assertion{RawXML: "Hi there"}
	enc := xml.NewEncoder(&b)
	enc.Encode(assertion)
	assert.False(t, strings.Contains(b.String(), "Hi"), b.String())
}
