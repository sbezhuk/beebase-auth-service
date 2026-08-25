// Package jwtauth issues and verifies signed JWT access tokens.
package jwtauth

import (
	"errors"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

// ErrInvalidToken is returned for any access token that fails to parse,
// fails signature verification, or has expired. Callers don't need (and
// shouldn't act on) the distinction between those cases.
var ErrInvalidToken = errors.New("invalid access token")

// Issuer signs and verifies access tokens with a single shared secret.
// It implements both application/auth.AccessTokenIssuer (Issue) and
// transport/http/middleware.AccessTokenParser (Parse).
type Issuer struct {
	secret []byte
	ttl    time.Duration
}

// NewIssuer returns an Issuer that signs tokens valid for ttl using secret.
func NewIssuer(secret string, ttl time.Duration) *Issuer {
	return &Issuer{secret: []byte(secret), ttl: ttl}
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

	signed, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString(i.secret)
	if err != nil {
		return "", time.Time{}, fmt.Errorf("jwtauth: sign: %w", err)
	}

	return signed, expiresAt, nil
}

// Parse verifies tokenString and returns the user ID it was issued for.
func (i *Issuer) Parse(tokenString string) (uuid.UUID, error) {
	var claims jwt.RegisteredClaims

	_, err := jwt.ParseWithClaims(tokenString, &claims, func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
		}
		return i.secret, nil
	})
	if err != nil {
		return uuid.Nil, ErrInvalidToken
	}

	userID, err := uuid.Parse(claims.Subject)
	if err != nil {
		return uuid.Nil, ErrInvalidToken
	}

	return userID, nil
}
