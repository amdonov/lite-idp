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

package saml

import (
	"reflect"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNewIssuer(t *testing.T) {
	type args struct {
		issuer string
	}
	tests := []struct {
		name string
		args args
		want *Issuer
	}{
		{"simple issuer", args{"myissuer"}, &Issuer{Format: "urn:oasis:names:tc:SAML:2.0:nameid-format:entity", Value: "myissuer"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := NewIssuer(tt.args.issuer); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("NewIssuer() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestNewID(t *testing.T) {
	assert.True(t, strings.HasPrefix(NewID(), "_"), "id doesn't start with _")
}
