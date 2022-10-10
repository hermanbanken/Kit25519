package kit25519

import (
	"crypto/sha256"
	"io"

	"github.com/aead/ecdh"
	"github.com/lestrrat-go/jwx/x25519"
	"golang.org/x/crypto/hkdf"
)

// Usage must match Swift implementation in Curve25519.swift
// https://pkg.go.dev/golang.org/x/crypto/hkdf#example-package-Usage
func HkdfDerivedSymmetricKey(c25519our x25519.PrivateKey, c25519theirs x25519.PublicKey, salt, sharedInfo []byte) []byte {
	c25519 := ecdh.X25519()
	if err := c25519.Check([]byte(c25519theirs)); err != nil {
		panic(err)
	}
	secret := c25519.ComputeSecret([]byte(c25519our)[0:32], []byte(c25519theirs))

	// Generate one 32-byte (256 bit) derive key
	hkdf := hkdf.New(sha256.New, secret, salt, sharedInfo)
	key := make([]byte, 32)
	if _, err := io.ReadFull(hkdf, key); err != nil {
		panic(err)
	}
	return key
}
