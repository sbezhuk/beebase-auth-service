//go:build integration

package postgres_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/sbezhuk/beebase-auth-service/internal/domain/loginchallenge"
	repopostgres "github.com/sbezhuk/beebase-auth-service/internal/repository/postgres"
)

func TestLoginChallengeRepository_CreateAndGetByHash(t *testing.T) {
	pool := testPool(t)
	ctx := context.Background()

	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin tx: %v", err)
	}
	t.Cleanup(func() { _ = tx.Rollback(ctx) })

	u := seedUser(t, ctx, tx, "challenge-create@example.com")
	repo := repopostgres.NewLoginChallengeRepository(tx)

	c := loginchallenge.New(u.ID, "hash-of-challenge-token", time.Hour)
	if err := repo.Create(ctx, c); err != nil {
		t.Fatalf("Create: %v", err)
	}

	got, err := repo.GetByHash(ctx, c.TokenHash)
	if err != nil {
		t.Fatalf("GetByHash: %v", err)
	}
	if got.ID != c.ID || got.UserID != u.ID {
		t.Errorf("GetByHash returned %+v, want matching %+v", got, c)
	}
	if got.IsConsumed() {
		t.Error("freshly created challenge should not be consumed")
	}
}

func TestLoginChallengeRepository_GetByHash_NotFound(t *testing.T) {
	pool := testPool(t)
	ctx := context.Background()

	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin tx: %v", err)
	}
	t.Cleanup(func() { _ = tx.Rollback(ctx) })

	_, err = repopostgres.NewLoginChallengeRepository(tx).GetByHash(ctx, "does-not-exist")
	if !errors.Is(err, loginchallenge.ErrNotFound) {
		t.Fatalf("GetByHash for unknown hash: got %v, want ErrNotFound", err)
	}
}

func TestLoginChallengeRepository_Consume(t *testing.T) {
	pool := testPool(t)
	ctx := context.Background()

	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin tx: %v", err)
	}
	t.Cleanup(func() { _ = tx.Rollback(ctx) })

	u := seedUser(t, ctx, tx, "challenge-consume@example.com")
	repo := repopostgres.NewLoginChallengeRepository(tx)

	c := loginchallenge.New(u.ID, "hash-to-consume", time.Hour)
	if err := repo.Create(ctx, c); err != nil {
		t.Fatalf("Create: %v", err)
	}

	if err := repo.Consume(ctx, c.ID); err != nil {
		t.Fatalf("Consume: %v", err)
	}

	got, err := repo.GetByHash(ctx, c.TokenHash)
	if err != nil {
		t.Fatalf("GetByHash: %v", err)
	}
	if !got.IsConsumed() {
		t.Error("challenge should be consumed after Consume")
	}

	// Idempotent: consuming again is not an error.
	if err := repo.Consume(ctx, c.ID); err != nil {
		t.Fatalf("second Consume: got %v, want nil (idempotent)", err)
	}
}
