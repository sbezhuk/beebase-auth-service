package postgres

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	appauth "github.com/sbezhuk/beebase-auth-service/internal/application/auth"
)

type deletionJobStore struct{ db *pgxpool.Pool }

func NewDeletionJobStore(db *pgxpool.Pool) *deletionJobStore { return &deletionJobStore{db: db} }

func (s *deletionJobStore) ClaimDeletion(ctx context.Context) (*appauth.DeletionJob, error) {
	tx, err := s.db.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)
	var j appauth.DeletionJob
	err = tx.QueryRow(ctx, `UPDATE account_deletion_jobs SET status='processing',attempt_count=attempt_count+1,lease_until=now()+interval '2 minutes',updated_at=now() WHERE id=(SELECT id FROM account_deletion_jobs WHERE status <> 'completed' AND next_attempt_at <= now() AND (lease_until IS NULL OR lease_until < now()) ORDER BY next_attempt_at FOR UPDATE SKIP LOCKED LIMIT 1) RETURNING id,user_id`).Scan(&j.ID, &j.UserID)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	rows, err := tx.Query(ctx, `SELECT service,status,attempt_count FROM account_deletion_steps WHERE job_id=$1 ORDER BY service`, j.ID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var step appauth.DeletionStep
		if err := rows.Scan(&step.Service, &step.Status, &step.AttemptCount); err != nil {
			return nil, err
		}
		j.Steps = append(j.Steps, step)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	return &j, nil
}

func (s *deletionJobStore) CompleteDeletionStep(ctx context.Context, jobID uuid.UUID, service string) error {
	_, err := s.db.Exec(ctx, `UPDATE account_deletion_steps SET status='completed',updated_at=now(),last_error=NULL WHERE job_id=$1 AND service=$2`, jobID, service)
	return err
}
func (s *deletionJobStore) RetryDeletionStep(ctx context.Context, jobID uuid.UUID, service string, attempt int, msg string) error {
	delay := time.Duration(1<<min(attempt, 8)) * time.Minute
	_, err := s.db.Exec(ctx, `UPDATE account_deletion_steps SET status='pending',attempt_count=$3,next_attempt_at=now()+$4::interval,last_error=$5,updated_at=now() WHERE job_id=$1 AND service=$2`, jobID, service, attempt, fmt.Sprintf("%d minutes", delay/time.Minute), msg)
	if err == nil {
		_, err = s.db.Exec(ctx, `UPDATE account_deletion_jobs SET status='pending',lease_until=NULL,updated_at=now() WHERE id=$1`, jobID)
	}
	return err
}
func (s *deletionJobStore) CompleteDeletionJob(ctx context.Context, jobID uuid.UUID) error {
	_, err := s.db.Exec(ctx, `UPDATE account_deletion_jobs SET status='completed',lease_until=NULL,last_error=NULL,updated_at=now() WHERE id=$1`, jobID)
	return err
}
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

var deletionServices = []string{"apiary", "hive", "inspection", "harvest", "media", "notification", "subscription"}

type DeletionStore struct{ db *pgxpool.Pool }

func NewDeletionStore(db *pgxpool.Pool) *DeletionStore { return &DeletionStore{db: db} }

// RequestDeletion is the single transaction which makes the account
// unusable and creates every durable cleanup step. The job has no FK to users
// because the user row is removed only after all steps complete.
func (s *DeletionStore) RequestDeletion(ctx context.Context, userID uuid.UUID) error {
	tx, err := s.db.Begin(ctx)
	if err != nil {
		return fmt.Errorf("deletion: begin: %w", err)
	}
	defer tx.Rollback(ctx)
	jobID := uuid.New()
	tag, err := tx.Exec(ctx, `UPDATE users SET deletion_status='deletion_pending', updated_at=now() WHERE id=$1 AND deletion_status='active'`, userID)
	if err != nil {
		return fmt.Errorf("deletion: mark pending: %w", err)
	}
	if tag.RowsAffected() == 0 {
		var status string
		if err := tx.QueryRow(ctx, `SELECT deletion_status FROM users WHERE id=$1`, userID).Scan(&status); errors.Is(err, pgx.ErrNoRows) {
			return fmt.Errorf("deletion: account is missing")
		} else if err != nil {
			return fmt.Errorf("deletion: check account status: %w", err)
		} else if status != "deletion_pending" {
			return fmt.Errorf("deletion: account is not deletable")
		}
		// A retry after the request was committed is intentionally a no-op.
		// The original job and its steps remain the single durable workflow.
		if err := tx.Commit(ctx); err != nil {
			return fmt.Errorf("deletion: commit existing request: %w", err)
		}
		return nil
	}
	if _, err = tx.Exec(ctx, `UPDATE refresh_tokens SET revoked_at=now() WHERE user_id=$1 AND revoked_at IS NULL`, userID); err != nil {
		return fmt.Errorf("deletion: revoke tokens: %w", err)
	}
	if err = tx.QueryRow(ctx, `INSERT INTO account_deletion_jobs (id,user_id,status) VALUES ($1,$2,'pending') ON CONFLICT (user_id) DO UPDATE SET updated_at=now() RETURNING id`, jobID, userID).Scan(&jobID); err != nil {
		return fmt.Errorf("deletion: create job: %w", err)
	}
	for _, name := range deletionServices {
		if _, err = tx.Exec(ctx, `INSERT INTO account_deletion_steps (job_id,service) VALUES ($1,$2) ON CONFLICT DO NOTHING`, jobID, name); err != nil {
			return fmt.Errorf("deletion: create step: %w", err)
		}
	}
	if err = tx.Commit(ctx); err != nil {
		return fmt.Errorf("deletion: commit: %w", err)
	}
	return nil
}

var _ appauth.DeletionRequester = (*DeletionStore)(nil)
