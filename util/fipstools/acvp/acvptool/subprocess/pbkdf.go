// Copyright (c) 2020, Google Inc.
//
// Permission to use, copy, modify, and/or distribute this software for any
// purpose with or without fee is hereby granted, provided that the above
// copyright notice and this permission notice appear in all copies.
//
// THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
// WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
// SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
// WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION
// OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN
// CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

package subprocess

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
)

// NOTE: all specs are currently based off of the examples in this page proveded by NIST:
// https://pages.nist.gov/ACVP/draft-celi-acvp-pbkdf.html

// pbkdf implements an ACVP algorithm by making requests to the subprocess
// to encrypt and decrypt with an PBKDF.
type pbkdf struct {
	algo string
}

type pbkdfVectorSet struct {
	Groups []pbkdfTestGroup `json:"testGroups"`
}

type pbkdfTestGroup struct {
	ID      uint64 `json:"tgId"`
	HmacAlg string `json:"hmacAlg"`
	Type    string `json:"testType"`
	Tests   []struct {
		ID         uint64 `json:"tcId"`
		KeyLen     uint64 `json:"keyLen"`
		SaltHex    string `json:"salt"`
		Pwd        string `json:"password"`
		Iterations uint64 `json:"iterationCount"`
	} `json:"tests"`
}

type pbkdfTestGroupResponse struct {
	ID    uint64              `json:"tgId"`
	Tests []pbkdfTestResponse `json:"tests"`
}

type pbkdfTestResponse struct {
	ID            uint64 `json:"tcId"`
	DerivedKeyHex string `json:"derivedKey"`
}

// List of supported HMAC Algorithms by NIST
var HmacAlgList map[string]bool = map[string]bool{
	"SHA-1":    true,
	"SHA2-224": true,
	"SHA2-256": true,
	"SHA2-384": true,
	"SHA2-512": true,
	"SHA3-224": true,
	"SHA3-256": true,
	"SHA3-384": true,
	"SHA3-512": true,
}

// Key and salt length mins and maxes as defined by NIST
var keyLenMin uint64 = 112
var keyLenMax uint64 = 4096
var iterationMin uint64 = 1
var iterationMax uint64 = 10000000
var saltLenMin int = 128
var saltLenMax int = 4096
var passwordLenMin int = 8
var passwordLenMax int = 4096

// List of supported PBKDF test types by NIST
var TestTypeList map[string]bool = map[string]bool{
	"AFT": true,
}

func (a *pbkdf) Process(vectorSet []byte, m Transactable) (interface{}, error) {
	var parsed pbkdfVectorSet
	if err := json.Unmarshal(vectorSet, &parsed); err != nil {
		return nil, err
	}

	var ret []pbkdfTestGroupResponse
	// See draft-celi-acvp-symmetric.html#table-6. (NIST no longer publish HTML
	// versions of the ACVP documents. You can find fragments in
	// https://github.com/usnistgov/ACVP.)
	for _, group := range parsed.Groups {
		response := pbkdfTestGroupResponse{
			ID: group.ID,
		}

		// Check for valid HMAC Algorithm
		_, algIn := HmacAlgList[group.HmacAlg]
		if !algIn {
			return nil, fmt.Errorf("test group %d has unsupported HMAC algorithm %q", group.ID, group.HmacAlg)
		}

		// Check if the test type is valid
		_, typeIn := TestTypeList[group.Type]
		if !typeIn {
			return nil, fmt.Errorf("test group %d has unsupported test type %q", group.ID, group.Type)
		}

		// Check each test in the test group
		for _, test := range group.Tests {

			if test.KeyLen > keyLenMax || test.KeyLen < keyLenMin {
				return nil, fmt.Errorf("test case %d/%d requests output key of length %d, but expected output key length between %d and %d", group.ID, test.ID, test.KeyLen, keyLenMin, keyLenMax)
			}

			// check length of salt against NIST min/max
			if len(test.SaltHex)*4 > saltLenMax || len(test.SaltHex)*4 < saltLenMin {
				return nil, fmt.Errorf("test case %d/%d contains salt %q of bit length %d, but expected bit length between %d and %d", group.ID, test.ID, test.SaltHex, len(test.SaltHex)*4, saltLenMin, saltLenMax)
			}

			// salt, err := hex.DecodeString(test.SaltHex)
			// if err != nil {
			// 	return nil, fmt.Errorf("failed to decode key in test case %d/%d: %s", group.ID, test.ID, err)
			// }

			if len(test.Pwd) > passwordLenMax || len(test.Pwd) < passwordLenMin {
				return nil, fmt.Errorf("test case %d/%d contains password %s of length %d, but expected password length between %d and %d", group.ID, test.ID, test.Pwd, len(test.Pwd), passwordLenMin, passwordLenMax)
			}

			if test.Iterations > iterationMax || test.Iterations < iterationMin {
				return nil, fmt.Errorf("test case %d/%d contains iteration count of %d, but expected iteration count between %d and %d", group.ID, test.ID, test.Iterations, iterationMin, iterationMax)
			}

			testResp := pbkdfTestResponse{ID: test.ID}
			// test to see if we're reading things right in go script
			fmt.Printf("Go File\n")
			fmt.Printf("%s\n", test.Pwd)
			fmt.Printf("%d\n", len(test.Pwd))
			fmt.Printf("%s\n", test.SaltHex)
			fmt.Printf("%d\n", len(test.SaltHex)*4)
			fmt.Printf("%d\n", test.Iterations)
			fmt.Printf("%s\n", group.HmacAlg)
			fmt.Printf("%d\n", test.KeyLen)
			var result [][]uint8
			// TODO: this probably doesn't work lol
			result, err := m.Transact(a.algo, 1, []byte(test.Pwd), uint32le(uint32(len(test.Pwd))),
				[]byte(test.SaltHex), uint32le(uint32(len(test.SaltHex)*4)),
				uint32le(uint32(test.Iterations)), []byte(group.HmacAlg),
				uint32le(uint32(test.KeyLen)))
			if err != nil {
				return nil, err
			}

			testResp.DerivedKeyHex = hex.EncodeToString(result[0])
			response.Tests = append(response.Tests, testResp)
		}

		ret = append(ret, response)
	}

	return ret, nil
}
