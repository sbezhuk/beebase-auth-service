package jwtauth_test

import (
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/sbezhuk/BeeBase-Server/internal/platform/jwtauth"
)

func TestIssuer_IssueAndParseRoundTrip(t *testing.T) {
	issuer := jwtauth.NewIssuer("test-secret", time.Minute)
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

	gotUserID, err := issuer.Parse(token)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if gotUserID != userID {
		t.Fatalf("Parse returned %s, want %s", gotUserID, userID)
	}
}

func TestIssuer_ParseRejectsExpiredToken(t *testing.T) {
	issuer := jwtauth.NewIssuer("test-secret", -time.Minute)

	token, _, err := issuer.Issue(uuid.New())
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}

	if _, err := issuer.Parse(token); err == nil {
		t.Fatal("Parse accepted an expired token")
	}
}

func TestIssuer_ParseRejectsTokenSignedWithDifferentSecret(t *testing.T) {
	issued := jwtauth.NewIssuer("secret-a", time.Minute)
	verifier := jwtauth.NewIssuer("secret-b", time.Minute)

	token, _, err := issued.Issue(uuid.New())
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}

	if _, err := verifier.Parse(token); err == nil {
		t.Fatal("Parse accepted a token signed with a different secret")
	}
}

func TestIssuer_ParseRejectsGarbage(t *testing.T) {
	issuer := jwtauth.NewIssuer("test-secret", time.Minute)

	if _, err := issuer.Parse("not-a-jwt"); err == nil {
		t.Fatal("Parse accepted a malformed token")
	}
}
