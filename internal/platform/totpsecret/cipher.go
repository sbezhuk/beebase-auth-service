// Package totpsecret encrypts TOTP secrets at rest with AES-256-GCM. Like
// platform/totp, this is not a swappable port - there is no anticipated
// alternative cipher - so it's called directly as a concrete package.
package totpsecret

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"io"
)

// KeySize is the required length, in bytes, of the key passed to NewCipher.
const KeySize = 32 // AES-256

// Cipher encrypts and decrypts TOTP secrets with AES-256-GCM.
type Cipher struct {
	aead cipher.AEAD
}

// NewCipher returns a Cipher using key, which must be exactly KeySize
// bytes.
func NewCipher(key []byte) (*Cipher, error) {
	if len(key) != KeySize {
		return nil, fmt.Errorf("totpsecret: key must be %d bytes, got %d", KeySize, len(key))
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("totpsecret: new cipher block: %w", err)
	}

	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("totpsecret: new gcm: %w", err)
	}

	return &Cipher{aead: aead}, nil
}

// Encrypt returns plaintext sealed with a fresh random nonce, prepended to
// the ciphertext so Decrypt can recover it.
func (c *Cipher) Encrypt(plaintext []byte) ([]byte, error) {
	nonce := make([]byte, c.aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("totpsecret: generate nonce: %w", err)
	}

	return c.aead.Seal(nonce, nonce, plaintext, nil), nil
}

// Decrypt reverses Encrypt, reading the nonce back off the front of
// ciphertext.
func (c *Cipher) Decrypt(ciphertext []byte) ([]byte, error) {
	nonceSize := c.aead.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, fmt.Errorf("totpsecret: ciphertext too short")
	}

	nonce, sealed := ciphertext[:nonceSize], ciphertext[nonceSize:]

	plaintext, err := c.aead.Open(nil, nonce, sealed, nil)
	if err != nil {
		return nil, fmt.Errorf("totpsecret: decrypt: %w", err)
	}

	return plaintext, nil
}
