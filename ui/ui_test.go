package ui

import (
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_idpUI_ServeHTTP(t *testing.T) {
	ts := httptest.NewServer(UI())
	defer ts.Close()
	// Get favicon
	// Get login form
	// Get missing page
	tests := []struct {
		name string
		page string
		want int
	}{
		{"favicon", "/favicon.ico", 200},
		{"login form", "/ui/login.html", 200},
		{"missing", "/ui/random.html", 404},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp, err := ts.Client().Get(ts.URL + tt.page)
			if err != nil {
				t.Errorf("ui error %v", err)
			}
			defer resp.Body.Close()
			assert.Equal(t, tt.want, resp.StatusCode)
		})
	}
}
