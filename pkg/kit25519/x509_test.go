// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package kit25519

import (
	"bytes"
	"crypto/ed25519"
	_ "crypto/sha256"
	_ "crypto/sha512"
	"encoding/pem"
	"testing"

	"github.com/lestrrat-go/jwx/x25519"
)

func testParsePKIXPublicKey(t *testing.T, pemBytes string) (pub any) {
	block, _ := pem.Decode([]byte(pemBytes))
	pub, err := ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		t.Fatalf("Failed to parse public key: %s", err)
	}

	pubBytes2, err := MarshalPKIXPublicKey(pub)
	if err != nil {
		t.Errorf("Failed to marshal public key for the second time: %s", err)
		return
	}
	if !bytes.Equal(pubBytes2, block.Bytes) {
		t.Errorf("Reserialization of public key didn't match. got %x, want %x", pubBytes2, block.Bytes)
	}
	return
}

func TestParsePKIXPublicKey(t *testing.T) {
	t.Run("Ed25519", func(t *testing.T) {
		pub := testParsePKIXPublicKey(t, pemEd25519Key)
		_, ok := pub.(ed25519.PublicKey)
		if !ok {
			t.Errorf("Value returned from ParsePKIXPublicKey was not an Ed25519 public key")
		}
	})
	t.Run("X25519", func(t *testing.T) {
		pub := testParsePKIXPublicKey(t, pemX25519Key)
		_, ok := pub.(x25519.PublicKey)
		if !ok {
			t.Errorf("Value returned from ParsePKIXPublicKey was not an X25519 public key")
		}
	})
}

// pemEd25519Key is the example from RFC 8410, Secrion 4.
var pemEd25519Key = `
-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEAGb9ECWmEzf6FQbrBZ9w7lshQhqowtrbLDFw4rXAxZuE=
-----END PUBLIC KEY-----
`

// Generated using
//
// openssl genpkey -algorithm x25519 |  openssl pkey -pubout
var pemX25519Key = `
-----BEGIN PUBLIC KEY-----
MCowBQYDK2VuAyEAHrZvPbCfK6jNpY2uCl9dbEqTWPxRvNBH9Zi3/DbDeno=
-----END PUBLIC KEY-----
`
