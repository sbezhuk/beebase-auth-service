//go:build integration

package postgres_test

import (
	"context"
	"fmt"
	"testing"

	"github.com/google/uuid"

	repopostgres "github.com/sbezhuk/beebase-auth-service/internal/repository/postgres"
)

func TestDeletionStore_RequestDeletionCreatesPendingSteps(t *testing.T) {
	pool := testPool(t)
	ctx := context.Background()
	userID := uuid.New()
	email := fmt.Sprintf("deletion-store-%s@example.com", userID)

	_, err := pool.Exec(ctx, `
		INSERT INTO users (id, email, password_hash, deletion_status)
		VALUES ($1, $2, 'test-hash', 'active')`, userID, email)
	if err != nil {
		t.Fatalf("seed user: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(ctx, `DELETE FROM users WHERE id=$1`, userID)
	})

	if err := repopostgres.NewDeletionStore(pool).RequestDeletion(ctx, userID); err != nil {
		t.Fatalf("RequestDeletion: %v", err)
	}

	var count int
	if err := pool.QueryRow(ctx, `
		SELECT count(*)
		FROM account_deletion_steps s
		JOIN account_deletion_jobs j ON j.id = s.job_id
		WHERE j.user_id=$1 AND s.status='pending'`, userID).Scan(&count); err != nil {
		t.Fatalf("count pending deletion steps: %v", err)
	}
	if count != 7 {
		t.Fatalf("pending deletion steps = %d, want 7", count)
	}

	var nullCount int
	if err := pool.QueryRow(ctx, `
		SELECT count(*)
		FROM account_deletion_steps s
		JOIN account_deletion_jobs j ON j.id = s.job_id
		WHERE j.user_id=$1 AND s.status IS NULL`, userID).Scan(&nullCount); err != nil {
		t.Fatalf("count null deletion step statuses: %v", err)
	}
	if nullCount != 0 {
		t.Fatalf("null deletion step statuses = %d, want 0", nullCount)
	}
}
