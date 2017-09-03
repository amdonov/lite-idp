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
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/amdonov/lite-idp/store"
	"github.com/amdonov/lite-idp/ui"
	"github.com/amdonov/xmlsig"
	"github.com/julienschmidt/httprouter"
	"github.com/spf13/viper"
)

type IDP struct {
	// You can include other routes by providing a router or
	// one will be created. Alternatively, you can add routes and
	// middleware to the Handler
	Router *httprouter.Router
	// Short term cache for saving state during authentication
	TempCache store.Cache
	// Longer term cache of authenticated users
	UserCache              store.Cache
	TLSConfig              *tls.Config
	PasswordValidator      PasswordValidator
	AttributeRetrievers    []AttributeRetriever
	MetadataHandler        http.HandlerFunc
	ArtifactResolveHandler http.HandlerFunc
	RedirectSSOHandler     http.HandlerFunc
	PasswordLoginHandler   http.HandlerFunc

	handler http.Handler
	signer  xmlsig.Signer

	// properties set or derived from configuration settings
	entityID                          string
	artifactResolutionServiceLocation string
	attributeServiceLocation          string
	singleSignOnServiceLocation       string
}

func (i *IDP) Handler() (http.Handler, error) {
	if i.handler == nil {
		i.configureConstants()
		err := i.configureCrypto()
		if err != nil {
			return nil, err
		}
		err = i.configureStores()
		if err != nil {
			return nil, err
		}
		err = i.buildRoutes()
		if err != nil {
			return nil, err
		}
		i.handler = i.Router
	}
	return i.handler, nil
}

func (i *IDP) configureConstants() {
	serverName := viper.GetString("server-name")
	i.entityID = viper.GetString("entity-id")
	if i.entityID == "" {
		i.entityID = fmt.Sprintf("https://%s/", serverName)
	}
	i.artifactResolutionServiceLocation = fmt.Sprintf("https://%s%s", serverName, viper.GetString("artifact-service-path"))
	i.attributeServiceLocation = fmt.Sprintf("https://%s%s", serverName, viper.GetString("attribute-service-path"))
	i.singleSignOnServiceLocation = fmt.Sprintf("https://%s%s", serverName, viper.GetString("sso-service-path"))
}

func (i *IDP) configureCrypto() error {
	if i.TLSConfig == nil {
		tlsConfig, err := ConfigureTLS()
		if err != nil {
			return err
		}
		i.TLSConfig = tlsConfig
	}
	if len(i.TLSConfig.Certificates) == 0 {
		return errors.New("tlsConfig does not contain a certificate")
	}
	cert := i.TLSConfig.Certificates[0]
	signer, err := xmlsig.NewSigner(cert)
	i.signer = signer
	return err
}

func (i *IDP) configureStores() error {
	if i.TempCache == nil {
		cache, err := store.New(time.Minute * 5)
		if err != nil {
			return err
		}
		i.TempCache = cache
	}
	if i.UserCache == nil {
		cache, err := store.New(time.Hour * 8)
		if err != nil {
			return err
		}
		i.UserCache = cache
	}
	return nil
}

func (i *IDP) buildRoutes() error {
	if i.Router == nil {
		i.Router = httprouter.New()
	}
	r := i.Router

	// Handle requests for metadata
	if i.MetadataHandler == nil {
		metadata, err := i.DefaultMetadataHandler()
		if err != nil {
			return err
		}
		i.MetadataHandler = metadata
	}
	r.HandlerFunc("GET", viper.GetString("metadata-path"), i.MetadataHandler)

	// Handle artifact resolution
	if i.ArtifactResolveHandler == nil {
		i.ArtifactResolveHandler = i.DefaultArtifactResolveHandler()
	}
	r.HandlerFunc("POST", viper.GetString("artifact-service-path"), i.ArtifactResolveHandler)

	// Handle redirect SSO requests
	if i.RedirectSSOHandler == nil {
		i.RedirectSSOHandler = i.DefaultRedirectSSOHandler()
	}
	r.HandlerFunc("GET", viper.GetString("sso-service-path"), i.RedirectSSOHandler)

	// Handle password logins
	if i.PasswordLoginHandler == nil {
		if i.PasswordValidator == nil {
			i.PasswordValidator = NewValidator()
		}
		i.PasswordLoginHandler = i.DefaultPasswordLoginHandler()
	}
	r.HandlerFunc("POST", "/ui/login.html", i.PasswordLoginHandler)

	// Serve up UI
	userInterface := ui.UI()
	r.Handler("GET", "/ui/*path", userInterface)
	r.Handler("GET", "/favicon.ico", userInterface)

	return nil
}

func getIP(request *http.Request) net.IP {
	addr := request.RemoteAddr
	if strings.Contains(addr, ":") {
		addr = strings.Split(addr, ":")[0]
	}
	return net.ParseIP(addr)
}
