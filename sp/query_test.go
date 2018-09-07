package sp

import (
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/amdonov/lite-idp/idp"
	"github.com/spf13/viper"
)

func TestQuery(t *testing.T) {
	viper.Set("tls-certificate", filepath.Join("testdata", "certificate.pem"))
	viper.Set("tls-private-key", filepath.Join("testdata", "key.pem"))

	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// TODO check incoming request
		f, _ := os.Open(filepath.Join("testdata", "response.xml"))
		defer f.Close()
		io.Copy(w, f)
	}))

	tlsConfigClient, err := idp.ConfigureTLS()
	if err != nil {
		t.Fatal(err)
	}
	serviceProvider, err := New(Configuration{
		EntityID:                    "https://www.jw.dev.gfclab.com/user",
		AssertionConsumerServiceURL: "http://test",
		Client:                      ts.Client(),
		IDPQueryEndpoint:            ts.URL,
		TLSConfig:                   tlsConfigClient,
	})
	if err != nil {
		t.Fatal(err)
	}
	assertion, err := serviceProvider.Query("CN=joe,C=US")
	if err != nil {
		t.Fatal(err)
	}
	if len(assertion.AttributeStatement.Attribute) != 1 {
		t.Fatal("expected to find 1 attribute")
	}
}
