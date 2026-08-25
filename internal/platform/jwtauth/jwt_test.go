package jwtauth_test

import (
	"crypto/ed25519"
	"encoding/base64"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"

	"github.com/sbezhuk/beebase-auth-service/internal/platform/jwtauth"
)

func generateKey(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	return pub, priv
}

func TestIssuer_IssuesVerifiableEdDSAToken(t *testing.T) {
	pub, priv := generateKey(t)
	issuer := jwtauth.NewIssuer(priv, jwtauth.KeyID(pub), time.Minute)
	userID := uuid.New()

	token, expiresAt, err := issuer.Issue(userID)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	if token == "" {
		t.Fatal("Issue returned an empty token")
	}
	if !expiresAt.After(time.Now()) {
		t.Fatal("Issue returned an expiry in the past")
	}

	var claims jwt.RegisteredClaims
	parsed, err := jwt.ParseWithClaims(token, &claims, func(tok *jwt.Token) (any, error) {
		return pub, nil
	}, jwt.WithValidMethods([]string{"EdDSA"}))
	if err != nil {
		t.Fatalf("verify with the matching public key: %v", err)
	}
	if !parsed.Valid {
		t.Fatal("token reported invalid")
	}
	if claims.Subject != userID.String() {
		t.Errorf("subject = %q, want %q", claims.Subject, userID.String())
	}
	if kid, _ := parsed.Header["kid"].(string); kid != jwtauth.KeyID(pub) {
		t.Errorf("kid header = %q, want %q", kid, jwtauth.KeyID(pub))
	}
}

func TestIssuer_TokenRejectedByWrongPublicKey(t *testing.T) {
	_, priv := generateKey(t)
	otherPub, _ := generateKey(t)

	issuer := jwtauth.NewIssuer(priv, "kid", time.Minute)
	token, _, err := issuer.Issue(uuid.New())
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}

	_, err = jwt.Parse(token, func(tok *jwt.Token) (any, error) {
		return otherPub, nil
	}, jwt.WithValidMethods([]string{"EdDSA"}))
	if err == nil {
		t.Fatal("token verified against a different public key")
	}
}

func TestKeyID_IsStableAndDistinct(t *testing.T) {
	pub1, _ := generateKey(t)
	pub2, _ := generateKey(t)

	first := jwtauth.KeyID(pub1)
	second := jwtauth.KeyID(pub1)
	if first != second {
		t.Errorf("KeyID(%v) = %q, then %q: want identical output", pub1, first, second)
	}
	if jwtauth.KeyID(pub1) == jwtauth.KeyID(pub2) {
		t.Error("KeyID collided for two different keys")
	}
}

func TestParsePrivateKey_RoundTrip(t *testing.T) {
	_, priv := generateKey(t)
	encoded := base64.StdEncoding.EncodeToString(priv)

	got, err := jwtauth.ParsePrivateKey(encoded)
	if err != nil {
		t.Fatalf("ParsePrivateKey: %v", err)
	}
	if !got.Equal(priv) {
		t.Error("ParsePrivateKey did not round-trip the original key")
	}
}

func TestParsePrivateKey_RejectsWrongLength(t *testing.T) {
	if _, err := jwtauth.ParsePrivateKey(base64.StdEncoding.EncodeToString([]byte("too-short"))); err == nil {
		t.Fatal("ParsePrivateKey accepted a key of the wrong length")
	}
}

func TestParsePrivateKey_RejectsInvalidBase64(t *testing.T) {
	if _, err := jwtauth.ParsePrivateKey("not-valid-base64!!!"); err == nil {
		t.Fatal("ParsePrivateKey accepted invalid base64")
	}
}
