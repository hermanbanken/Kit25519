// Copyright 2011 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package kit25519

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"encoding/hex"
	"reflect"
	"testing"

	"github.com/lestrrat-go/jwx/x25519"
)

// From RFC 8410, Section 7.
var pkcs8Ed25519PrivateKeyHex = `302e020100300506032b657004220420d4ee72dbf913584ad5b6d8f1f769f8ad3afe7c28cbf1d4fbe097a88f44755842`

// Generated using:
//
// openssl genpkey -algorithm x25519 | openssl pkcs8 -topk8 -nocrypt --outform der | xxd -p
var pkcs8X25519PrivateKeyHex = `302e020100300506032b656e0422042048975f7ac4ab68008cb772003b3949a283c9b13a9eca4d9b72e5480340afcc72`

func TestPKCS8(t *testing.T) {
	tests := []struct {
		name    string
		keyHex  string
		keyType reflect.Type
		curve   elliptic.Curve
	}{
		{
			name:    "Ed25519 private key",
			keyHex:  pkcs8Ed25519PrivateKeyHex,
			keyType: reflect.TypeOf(ed25519.PrivateKey{}),
		},
		{
			name:    "x25519 private key",
			keyHex:  pkcs8X25519PrivateKeyHex,
			keyType: reflect.TypeOf(x25519.PrivateKey{}),
		},
	}

	for _, test := range tests {
		derBytes, err := hex.DecodeString(test.keyHex)
		if err != nil {
			t.Errorf("%s: failed to decode hex: %s", test.name, err)
			continue
		}
		privKey, err := ParsePKCS8PrivateKey(derBytes)
		if err != nil {
			t.Errorf("%s: failed to decode PKCS#8: %s", test.name, err)
			continue
		}
		if reflect.TypeOf(privKey) != test.keyType {
			t.Errorf("%s: decoded PKCS#8 returned unexpected key type: %T", test.name, privKey)
			continue
		}
		if ecKey, isEC := privKey.(*ecdsa.PrivateKey); isEC && ecKey.Curve != test.curve {
			t.Errorf("%s: decoded PKCS#8 returned unexpected curve %#v", test.name, ecKey.Curve)
			continue
		}
		reserialised, err := MarshalPKCS8PrivateKey(privKey)
		if err != nil {
			t.Errorf("%s: failed to marshal into PKCS#8: %s", test.name, err)
			continue
		}
		if !bytes.Equal(derBytes, reserialised) {
			t.Errorf("%s: marshaled PKCS#8 didn't match original: got %x, want %x", test.name, reserialised, derBytes)
			continue
		}
	}
}
