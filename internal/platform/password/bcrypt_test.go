package password_test

import (
	"testing"

	"golang.org/x/crypto/bcrypt"

	"github.com/sbezhuk/BeeBase-Server/internal/platform/password"
)

func TestBcryptHasher_HashAndVerify(t *testing.T) {
	h := password.NewBcryptHasher(bcrypt.MinCost)

	hash, err := h.Hash("correct horse battery staple")
	if err != nil {
		t.Fatalf("Hash: %v", err)
	}
	if hash == "correct horse battery staple" {
		t.Fatal("Hash returned the plaintext password unchanged")
	}

	if err := h.Verify(hash, "correct horse battery staple"); err != nil {
		t.Fatalf("Verify with correct password: %v", err)
	}
}

func TestBcryptHasher_VerifyWrongPassword(t *testing.T) {
	h := password.NewBcryptHasher(bcrypt.MinCost)

	hash, err := h.Hash("correct horse battery staple")
	if err != nil {
		t.Fatalf("Hash: %v", err)
	}

	if err := h.Verify(hash, "wrong password"); err == nil {
		t.Fatal("Verify with wrong password: expected error, got nil")
	}
}

func TestNewBcryptHasher_InvalidCostFallsBackToDefault(t *testing.T) {
	h := password.NewBcryptHasher(-5)

	hash, err := h.Hash("password123")
	if err != nil {
		t.Fatalf("Hash: %v", err)
	}
	if err := h.Verify(hash, "password123"); err != nil {
		t.Fatalf("Verify: %v", err)
	}
}
