package kit25519

import (
	"bytes"
	"crypto/rand"
	"errors"
	"fmt"
	"testing"

	"github.com/lestrrat-go/jwx/x25519"
	"golang.org/x/crypto/chacha20poly1305"
)

const (
	// Public data, but required for HKDF key derivation.
	// Note about salt & shared info (from https://soatok.blog/2021/11/17/understanding-hkdf/):
	// it is more secure to leave the salt empty and use different shared info, than using different salts.
	CryptoSharedInfo = "example-message-encryption"
	CryptoSalt       = ""
)

func decrypt(key []byte, data []byte) ([]byte, error) {
	// Swift counterpart uses ChaCha20-Poly1305
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, err
	}
	if len(data) < aead.NonceSize() {
		return nil, errors.New("ciphertext too short")
	}

	// Split nonce and ciphertext.
	nonce, ciphertext := data[:aead.NonceSize()], data[aead.NonceSize():]

	// Decrypt the message and check it wasn't tampered with.
	return aead.Open(nil, nonce, ciphertext, nil)
}

func encrypt(key []byte, data []byte) ([]byte, error) {
	// Swift counterpart uses ChaCha20-Poly1305
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, err
	}
	if len(data) < aead.NonceSize() {
		return nil, errors.New("ciphertext too short")
	}

	nonce := make([]byte, aead.NonceSize())
	if _, err = rand.Read(nonce); err != nil {
		return nil, err
	}

	// Decrypt the message and check it wasn't tampered with.
	return aead.Seal(nonce, nonce, data, nil), nil
}

func TestExampleECDHChachaPolyDecrypt(t *testing.T) {
	ourPublic, ourSecret, _ := x25519.GenerateKey(rand.Reader)
	theirPublic, theirSecret, _ := x25519.GenerateKey(rand.Reader)
	data := bytes.Repeat([]byte("secret"), 10)

	// We encrypt
	encrypt := func(data []byte) ([]byte, error) {
		symmetric := HkdfDerivedSymmetricKey(ourSecret, theirPublic, nil, []byte(CryptoSharedInfo))
		return encrypt(symmetric, data)
	}

	encrypted, err := encrypt(data)
	if err != nil {
		t.Error(err)
	}

	// Other party decrypts
	decrypt := func(data []byte) ([]byte, error) {
		symmetric := HkdfDerivedSymmetricKey(theirSecret, ourPublic, nil, []byte(CryptoSharedInfo))
		return decrypt(symmetric, data)
	}

	decrypted, err := decrypt(encrypted)
	if err != nil {
		t.Error(err)
	}

	if bytes.Equal(data, decrypted) {
		fmt.Println("OK")
	} else {
		fmt.Println("Not OK")
		t.Fail()
	}
}
