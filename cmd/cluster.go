// Copyright © 2018 Aaron Donovan <amdonov@gmail.com>
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
	"github.com/amdonov/lite-idp/idp"
	"github.com/amdonov/lite-idp/store/redis"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// ClusterCmd represents the cluster command
func ClusterCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "cluster",
		Short: "runs idp with shared state",
		Long: `Support running multiple instances of idp. 
Cache data is stored in Redis.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			tempCache, err := redis.New(viper.GetDuration("temp-cache-duration"))
			if err != nil {
				return err
			}
			userCache, err := redis.New(viper.GetDuration("user-cache-duration"))
			if err != nil {
				return err
			}
			return ServeCmd(&idp.IDP{
				TempCache: tempCache,
				UserCache: userCache,
			}).RunE(cmd, args)
		},
		Args: cobra.NoArgs,
	}
}
