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

package redis

import (
	"time"

	"github.com/amdonov/lite-idp/store"
	"github.com/go-redis/redis"
	"github.com/spf13/viper"
)

func New(duration time.Duration) (store.Cache, error) {
	redisdb := redis.NewClient(&redis.Options{
		Addr:     viper.GetString("redis.address"),
		Password: viper.GetString("redis.password"),
	})
	return &cache{redisdb, duration}, nil
}

type cache struct {
	client   *redis.Client
	duration time.Duration
}

func (c *cache) Set(key string, entry []byte) error {
	return c.client.Set(key, entry, c.duration).Err()
}
func (c *cache) Get(key string) ([]byte, error) {
	res, err := c.client.Get(key).Result()
	if err != nil {
		return nil, err
	}
	return []byte(res), nil
}
func (c *cache) Delete(key string) error {
	return c.client.Del(key).Err()
}

func init() {
	viper.SetDefault("redis.address", "127.0.0.1:6379")
	viper.SetDefault("redis.password", "")
}
