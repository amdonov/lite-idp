// Copyright © 2019 David Morgan <dmorgan81@gmail.com>
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

package sign

import (
	"github.com/moov-io/signedxml"
)

type signedxmlValidator struct {
}

func NewValidator() Validator {
	return &signedxmlValidator{}
}

func (v *signedxmlValidator) Validate(xml string) ([]string, error) {
	validator, err := signedxml.NewValidator(xml)
	if err != nil {
		return nil, err
	}

	return validator.ValidateReferences()
}
