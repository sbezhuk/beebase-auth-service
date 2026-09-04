//go:build integration

package postgres_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/sbezhuk/beebase-auth-service/internal/domain/passwordreset"
	repopostgres "github.com/sbezhuk/beebase-auth-service/internal/repository/postgres"
)

func TestPasswordResetFlowRepository_CreateAndGetByFlowTokenHash(t *testing.T) {
	pool := testPool(t)
	ctx := context.Background()

	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin tx: %v", err)
	}
	t.Cleanup(func() { _ = tx.Rollback(ctx) })

	u := seedUser(t, ctx, tx, "reset-create@example.com")
	repo := repopostgres.NewPasswordResetFlowRepository(tx)

	userID := u.ID
	flow := passwordreset.New(&userID, "hash-of-flow-token", time.Hour)
	if err := repo.Create(ctx, flow); err != nil {
		t.Fatalf("Create: %v", err)
	}

	got, err := repo.GetByFlowTokenHash(ctx, flow.FlowTokenHash)
	if err != nil {
		t.Fatalf("GetByFlowTokenHash: %v", err)
	}
	if got.ID != flow.ID || got.UserID == nil || *got.UserID != userID {
		t.Errorf("GetByFlowTokenHash returned %+v, want matching %+v", got, flow)
	}
	if got.IsOTPVerified() {
		t.Error("freshly created flow should not be OTP-verified")
	}
}

func TestPasswordResetFlowRepository_Create_NilUserID(t *testing.T) {
	pool := testPool(t)
	ctx := context.Background()

	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin tx: %v", err)
	}
	t.Cleanup(func() { _ = tx.Rollback(ctx) })

	repo := repopostgres.NewPasswordResetFlowRepository(tx)

	// An ineligible request (unknown email, or no 2FA) stores a flow with
	// no user - this must round-trip cleanly, not error on a NULL user_id.
	flow := passwordreset.New(nil, "hash-of-ineligible-flow-token", time.Hour)
	if err := repo.Create(ctx, flow); err != nil {
		t.Fatalf("Create with nil UserID: %v", err)
	}

	got, err := repo.GetByFlowTokenHash(ctx, flow.FlowTokenHash)
	if err != nil {
		t.Fatalf("GetByFlowTokenHash: %v", err)
	}
	if got.UserID != nil {
		t.Errorf("UserID = %v, want nil", got.UserID)
	}
}

func TestPasswordResetFlowRepository_GetByFlowTokenHash_NotFound(t *testing.T) {
	pool := testPool(t)
	ctx := context.Background()

	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin tx: %v", err)
	}
	t.Cleanup(func() { _ = tx.Rollback(ctx) })

	_, err = repopostgres.NewPasswordResetFlowRepository(tx).GetByFlowTokenHash(ctx, "does-not-exist")
	if !errors.Is(err, passwordreset.ErrNotFound) {
		t.Fatalf("GetByFlowTokenHash for unknown hash: got %v, want ErrNotFound", err)
	}
}

func TestPasswordResetFlowRepository_Update_IssuesResetTokenAndConsumes(t *testing.T) {
	pool := testPool(t)
	ctx := context.Background()

	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin tx: %v", err)
	}
	t.Cleanup(func() { _ = tx.Rollback(ctx) })

	u := seedUser(t, ctx, tx, "reset-update@example.com")
	repo := repopostgres.NewPasswordResetFlowRepository(tx)

	userID := u.ID
	flow := passwordreset.New(&userID, "hash-of-flow-token-2", time.Hour)
	if err := repo.Create(ctx, flow); err != nil {
		t.Fatalf("Create: %v", err)
	}

	flow.MarkOTPVerified()
	flow.IssueResetToken("hash-of-reset-token", time.Hour)
	if err := repo.Update(ctx, flow); err != nil {
		t.Fatalf("Update (issue reset token): %v", err)
	}

	byReset, err := repo.GetByResetTokenHash(ctx, "hash-of-reset-token")
	if err != nil {
		t.Fatalf("GetByResetTokenHash: %v", err)
	}
	if !byReset.IsOTPVerified() {
		t.Error("flow should be OTP-verified")
	}

	byReset.Consume()
	if err := repo.Update(ctx, byReset); err != nil {
		t.Fatalf("Update (consume): %v", err)
	}

	final, err := repo.GetByResetTokenHash(ctx, "hash-of-reset-token")
	if err != nil {
		t.Fatalf("GetByResetTokenHash after consume: %v", err)
	}
	if !final.IsConsumed() {
		t.Error("flow should be consumed")
	}
}

func TestPasswordResetFlowRepository_Update_NotFound(t *testing.T) {
	pool := testPool(t)
	ctx := context.Background()

	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin tx: %v", err)
	}
	t.Cleanup(func() { _ = tx.Rollback(ctx) })

	flow := passwordreset.New(nil, "never-created-hash", time.Hour)

	err = repopostgres.NewPasswordResetFlowRepository(tx).Update(ctx, flow)
	if !errors.Is(err, passwordreset.ErrNotFound) {
		t.Fatalf("Update of never-created flow: got %v, want ErrNotFound", err)
	}
}
