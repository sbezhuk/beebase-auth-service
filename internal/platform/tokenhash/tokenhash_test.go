package tokenhash_test

import (
	"testing"

	"github.com/sbezhuk/beebase-auth-service/internal/platform/tokenhash"
)

func TestGenerate_ProducesUniqueTokens(t *testing.T) {
	a, err := tokenhash.Generate()
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	b, err := tokenhash.Generate()
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}

	if a == b {
		t.Fatal("Generate returned the same token twice")
	}
	if a == "" || b == "" {
		t.Fatal("Generate returned an empty token")
	}
}

func TestHash_IsDeterministic(t *testing.T) {
	raw := "some-opaque-token"

	first := tokenhash.Hash(raw)
	second := tokenhash.Hash(raw)

	if first != second {
		t.Fatalf("Hash(%q) = %q, then %q: want identical output", raw, first, second)
	}
}

func TestHash_DiffersForDifferentInput(t *testing.T) {
	if tokenhash.Hash("token-a") == tokenhash.Hash("token-b") {
		t.Fatal("Hash produced the same output for different input")
	}
}

func TestHash_DoesNotReturnTheRawToken(t *testing.T) {
	raw := "some-opaque-token"

	if tokenhash.Hash(raw) == raw {
		t.Fatal("Hash returned the raw token unchanged")
	}
}
