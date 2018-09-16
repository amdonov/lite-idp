package idp

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
)

func TestIDP_DefaultQueryHandler(t *testing.T) {
	i := &IDP{}
	ts := getTestIDP(t, i)
	defer ts.Close()
	in, err := os.Open(filepath.Join("testdata", "attribute-query-request.xml"))
	if err != nil {
		t.Fatal(err)
	}
	resp, err := ts.Client().Post(ts.URL+viper.GetString("attribute-service-path"), "text/xml", in)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	assert.Equal(t, 200, resp.StatusCode)
}
