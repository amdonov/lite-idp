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
	"crypto/tls"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/amdonov/lite-idp/store"
	"github.com/amdonov/xmlsig"
)

type IDP interface {
	Metadata() (http.HandlerFunc, error)
	SSOService() (http.HandlerFunc, error)
	PasswordLogin() http.HandlerFunc
	ArtifactResolve() http.HandlerFunc
}

type Configuration struct {
	EntityID                          string
	SingleSignOnServiceLocation       string
	ArtifactResolutionServiceLocation string
	AttributeServiceLocation          string
	TLSConfig                         *tls.Config
	PasswordValidator                 PasswordValidator
}

func New(conf Configuration) (IDP, error) {
	cert := conf.TLSConfig.Certificates[0]

	signer, err := xmlsig.NewSigner(cert)
	if err != nil {
		return nil, err
	}
	tempCache, err := store.New(time.Minute * 5)
	if err != nil {
		return nil, err
	}
	userCache, err := store.New(time.Hour * 8)
	if err != nil {
		return nil, err
	}
	return &idp{conf, signer, tempCache, userCache}, nil
}

type idp struct {
	configuration Configuration
	signer        xmlsig.Signer
	tempCache     store.Cache
	userCache     store.Cache
}

func getIP(request *http.Request) net.IP {
	addr := request.RemoteAddr
	if strings.Contains(addr, ":") {
		addr = strings.Split(addr, ":")[0]
	}
	return net.ParseIP(addr)
}
