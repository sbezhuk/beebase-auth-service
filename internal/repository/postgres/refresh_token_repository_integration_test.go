//go:build integration

package postgres_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/sbezhuk/beebase-auth-service/internal/domain/token"
	"github.com/sbezhuk/beebase-auth-service/internal/domain/user"
	repopostgres "github.com/sbezhuk/beebase-auth-service/internal/repository/postgres"
)

// seedUser inserts a user directly (via the same repository under test)
// so refresh_tokens' foreign key constraint on user_id is satisfied.
func seedUser(t *testing.T, ctx context.Context, db repopostgres.Querier, email string) *user.User {
	t.Helper()

	u := user.New(email, "hashed-password")
	if err := repopostgres.NewUserRepository(db).Create(ctx, u); err != nil {
		t.Fatalf("seed user: %v", err)
	}
	return u
}

func TestRefreshTokenRepository_CreateAndGetByHash(t *testing.T) {
	pool := testPool(t)
	ctx := context.Background()

	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin tx: %v", err)
	}
	t.Cleanup(func() { _ = tx.Rollback(ctx) })

	u := seedUser(t, ctx, tx, "refresh-create@example.com")
	repo := repopostgres.NewRefreshTokenRepository(tx)

	rt := token.New(u.ID, "hash-of-opaque-token", time.Hour)
	if err := repo.Create(ctx, rt); err != nil {
		t.Fatalf("Create: %v", err)
	}

	got, err := repo.GetByHash(ctx, rt.TokenHash)
	if err != nil {
		t.Fatalf("GetByHash: %v", err)
	}
	if got.ID != rt.ID || got.UserID != u.ID {
		t.Errorf("GetByHash returned %+v, want matching %+v", got, rt)
	}
	if got.IsRevoked() {
		t.Error("freshly created token should not be revoked")
	}
}

func TestRefreshTokenRepository_GetByHash_NotFound(t *testing.T) {
	pool := testPool(t)
	ctx := context.Background()

	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin tx: %v", err)
	}
	t.Cleanup(func() { _ = tx.Rollback(ctx) })

	_, err = repopostgres.NewRefreshTokenRepository(tx).GetByHash(ctx, "does-not-exist")
	if !errors.Is(err, token.ErrNotFound) {
		t.Fatalf("GetByHash for unknown hash: got %v, want ErrNotFound", err)
	}
}

func TestRefreshTokenRepository_Revoke(t *testing.T) {
	pool := testPool(t)
	ctx := context.Background()

	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin tx: %v", err)
	}
	t.Cleanup(func() { _ = tx.Rollback(ctx) })

	u := seedUser(t, ctx, tx, "refresh-revoke@example.com")
	repo := repopostgres.NewRefreshTokenRepository(tx)

	rt := token.New(u.ID, "hash-to-revoke", time.Hour)
	if err := repo.Create(ctx, rt); err != nil {
		t.Fatalf("Create: %v", err)
	}

	if err := repo.Revoke(ctx, rt.ID); err != nil {
		t.Fatalf("Revoke: %v", err)
	}

	got, err := repo.GetByHash(ctx, rt.TokenHash)
	if err != nil {
		t.Fatalf("GetByHash: %v", err)
	}
	if !got.IsRevoked() {
		t.Error("token should be revoked after Revoke")
	}
}

func TestRefreshTokenRepository_RevokeAllForUser(t *testing.T) {
	pool := testPool(t)
	ctx := context.Background()

	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin tx: %v", err)
	}
	t.Cleanup(func() { _ = tx.Rollback(ctx) })

	u := seedUser(t, ctx, tx, "refresh-revoke-all@example.com")
	repo := repopostgres.NewRefreshTokenRepository(tx)

	first := token.New(u.ID, "hash-family-1", time.Hour)
	second := token.New(u.ID, "hash-family-2", time.Hour)
	if err := repo.Create(ctx, first); err != nil {
		t.Fatalf("Create first: %v", err)
	}
	if err := repo.Create(ctx, second); err != nil {
		t.Fatalf("Create second: %v", err)
	}

	if err := repo.RevokeAllForUser(ctx, u.ID); err != nil {
		t.Fatalf("RevokeAllForUser: %v", err)
	}

	for _, hash := range []string{first.TokenHash, second.TokenHash} {
		got, err := repo.GetByHash(ctx, hash)
		if err != nil {
			t.Fatalf("GetByHash(%q): %v", hash, err)
		}
		if !got.IsRevoked() {
			t.Errorf("token %q should be revoked after RevokeAllForUser", hash)
		}
	}
}
