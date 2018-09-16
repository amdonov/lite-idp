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

package cmd

import (
	"context"
	"net/http"
	"os"
	"os/signal"

	"github.com/amdonov/lite-idp/idp"
	"github.com/gorilla/handlers"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// ServeCmd represents the serve command
func ServeCmd(indentityProvider *idp.IDP) *cobra.Command {
	return &cobra.Command{
		Use:   "serve",
		Short: "runs idp server",
		RunE: func(cmd *cobra.Command, args []string) error {
			// Listen for shutdown signal
			stop := make(chan os.Signal, 1)
			signal.Notify(stop, os.Interrupt)
			handler, err := indentityProvider.Handler()
			if err != nil {
				return err
			}
			server := &http.Server{
				TLSConfig: indentityProvider.TLSConfig,
				Handler:   handlers.CombinedLoggingHandler(os.Stdout, hsts(handler)),
				Addr:      viper.GetString("listen-address"),
			}
			go func() {
				// Handle shutdown signal
				<-stop
				server.Shutdown(context.Background())
			}()

			log.Infof("listening for connections on %s", server.Addr)
			if err = server.ListenAndServeTLS("", ""); err != http.ErrServerClosed {
				return err
			}
			log.Info("server shutdown cleanly")
			return nil
		},
		Args: cobra.NoArgs,
	}
}

type hstsHandler struct {
	handler http.Handler
}

func (h *hstsHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Add("Strict-Transport-Security", "max-age=63072000; includeSubDomains")
	h.handler.ServeHTTP(w, r)
}

func hsts(h http.Handler) http.Handler {
	return &hstsHandler{h}
}
