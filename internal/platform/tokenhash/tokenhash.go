// Package tokenhash generates opaque refresh tokens and hashes them for
// storage. The raw token is high-entropy random data handed to the client
// once; only its hash is ever persisted, so it's hashed with plain SHA-256
// rather than a slow password KDF like bcrypt.
package tokenhash

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
)

// rawTokenBytes is the amount of random entropy in each generated token.
const rawTokenBytes = 32

// Generate returns a new random, URL-safe opaque token.
func Generate() (string, error) {
	b := make([]byte, rawTokenBytes)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("tokenhash: generate: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// Hash returns the hex-encoded SHA-256 digest of raw, for storage and
// lookup instead of the raw token itself.
func Hash(raw string) string {
	sum := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(sum[:])
}
