// Copyright © 2017 Aaron Donovan <amdonov@gmail.com>
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package model

import (
	"reflect"
	"testing"

	"github.com/amdonov/lite-idp/saml"
)

func TestNewAuthnRequest(t *testing.T) {
	type args struct {
		src        *saml.AuthnRequest
		relayState string
	}
	tests := []struct {
		name    string
		args    args
		want    *AuthnRequest
		wantErr bool
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := NewAuthnRequest(tt.args.src, tt.args.relayState)
			if (err != nil) != tt.wantErr {
				t.Errorf("NewAuthnRequest() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("NewAuthnRequest() = %v, want %v", got, tt.want)
			}
		})
	}
}
