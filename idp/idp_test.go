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

package idp

import (
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/spf13/viper"
)

func getTestIDP(t *testing.T, i *IDP) *httptest.Server {
	viper.Set("tls-certificate", filepath.Join("testdata", "certificate.pem"))
	viper.Set("tls-private-key", filepath.Join("testdata", "key.pem"))
	handler, err := i.Handler()
	if err != nil {
		t.Fatal(err)
	}
	return httptest.NewTLSServer(handler)
}
