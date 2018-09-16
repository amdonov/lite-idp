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
	"testing"
	"time"

	"github.com/alicebob/miniredis"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
)

func TestNew(t *testing.T) {
	s, err := miniredis.Run()
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	viper.Set("redis.address", s.Addr())
	value := []byte("value")
	cache, err := New(time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if err = cache.Set("test", value); err != nil {
		t.Fatal(err)
	}
	res, err := cache.Get("test")
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, value, res)
	cache.Delete("test")
	_, err = cache.Get("test")
	if err == nil {
		t.Fatal("should not have returned value")
	}
}
