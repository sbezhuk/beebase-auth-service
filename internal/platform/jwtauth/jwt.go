// Package jwtauth issues EdDSA-signed JWT access tokens. auth-service is
// the only service holding the private key; every other service verifies
// tokens against the matching public key via beebase-common/authmw,
// fetched from this service's JWKS endpoint, and can never mint one.
package jwtauth

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

// Issuer signs access tokens with an Ed25519 private key.
type Issuer struct {
	priv ed25519.PrivateKey
	kid  string
	ttl  time.Duration
}

// NewIssuer returns an Issuer that signs tokens valid for ttl using priv,
// tagged with kid so verifiers can match it to the right public key.
func NewIssuer(priv ed25519.PrivateKey, kid string, ttl time.Duration) *Issuer {
	return &Issuer{priv: priv, kid: kid, ttl: ttl}
}

// Issue signs a new access token for userID, returning the token and its
// expiry time.
func (i *Issuer) Issue(userID uuid.UUID) (string, time.Time, error) {
	now := time.Now().UTC()
	expiresAt := now.Add(i.ttl)

	claims := jwt.RegisteredClaims{
		Subject:   userID.String(),
		IssuedAt:  jwt.NewNumericDate(now),
		ExpiresAt: jwt.NewNumericDate(expiresAt),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodEdDSA, claims)
	token.Header["kid"] = i.kid

	signed, err := token.SignedString(i.priv)
	if err != nil {
		return "", time.Time{}, fmt.Errorf("jwtauth: sign: %w", err)
	}

	return signed, expiresAt, nil
}

// KeyID derives a stable identifier for pub, used both as the "kid" header
// on issued tokens and as the key ID in the JWKS document, so a verifier
// can match one to the other.
func KeyID(pub ed25519.PublicKey) string {
	sum := sha256.Sum256(pub)
	return hex.EncodeToString(sum[:8])
}

// ParsePrivateKey decodes a standard-base64-encoded Ed25519 private key
// (the 64-byte seed+public form produced by ed25519.GenerateKey).
func ParsePrivateKey(encoded string) (ed25519.PrivateKey, error) {
	raw, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, fmt.Errorf("jwtauth: decode private key: %w", err)
	}
	if len(raw) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("jwtauth: private key must be %d bytes, got %d", ed25519.PrivateKeySize, len(raw))
	}
	return ed25519.PrivateKey(raw), nil
}
