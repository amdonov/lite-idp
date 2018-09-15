package ui

import (
	"net/http"
	"testing"
)

func Test_idpUI_ServeHTTP(t *testing.T) {
	type fields struct {
		h             http.Handler
		prefixHandler http.Handler
	}
	type args struct {
		w   http.ResponseWriter
		req *http.Request
	}
	tests := []struct {
		name   string
		fields fields
		args   args
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := &idpUI{
				h:             tt.fields.h,
				prefixHandler: tt.fields.prefixHandler,
			}
			s.ServeHTTP(tt.args.w, tt.args.req)
		})
	}
}
