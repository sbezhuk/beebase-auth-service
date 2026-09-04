package postgres

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"

	"github.com/sbezhuk/beebase-auth-service/internal/domain/passwordreset"
)

// PasswordResetFlowRepository implements domain/passwordreset.Repository
// against PostgreSQL.
type PasswordResetFlowRepository struct {
	db Querier
}

// NewPasswordResetFlowRepository returns a PasswordResetFlowRepository
// backed by db.
func NewPasswordResetFlowRepository(db Querier) *PasswordResetFlowRepository {
	return &PasswordResetFlowRepository{db: db}
}

func (r *PasswordResetFlowRepository) Create(ctx context.Context, f *passwordreset.PasswordResetFlow) error {
	const q = `
		INSERT INTO password_reset_flows (
			id, user_id, flow_token_hash, otp_verified_at, otp_attempts,
			reset_token_hash, reset_token_expires_at, expires_at, consumed_at, created_at
		)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
	`

	_, err := r.db.Exec(ctx, q,
		f.ID, f.UserID, f.FlowTokenHash, f.OTPVerifiedAt, f.OTPAttempts,
		f.ResetTokenHash, f.ResetTokenExpiresAt, f.ExpiresAt, f.ConsumedAt, f.CreatedAt,
	)
	if err != nil {
		return fmt.Errorf("postgres: create password reset flow: %w", err)
	}

	return nil
}

func (r *PasswordResetFlowRepository) GetByFlowTokenHash(ctx context.Context, hash string) (*passwordreset.PasswordResetFlow, error) {
	const q = `
		SELECT id, user_id, flow_token_hash, otp_verified_at, otp_attempts,
			reset_token_hash, reset_token_expires_at, expires_at, consumed_at, created_at
		FROM password_reset_flows
		WHERE flow_token_hash = $1
	`
	return r.scanOne(ctx, q, hash)
}

func (r *PasswordResetFlowRepository) GetByResetTokenHash(ctx context.Context, hash string) (*passwordreset.PasswordResetFlow, error) {
	const q = `
		SELECT id, user_id, flow_token_hash, otp_verified_at, otp_attempts,
			reset_token_hash, reset_token_expires_at, expires_at, consumed_at, created_at
		FROM password_reset_flows
		WHERE reset_token_hash = $1
	`
	return r.scanOne(ctx, q, hash)
}

func (r *PasswordResetFlowRepository) Update(ctx context.Context, f *passwordreset.PasswordResetFlow) error {
	const q = `
		UPDATE password_reset_flows
		SET otp_verified_at = $2, otp_attempts = $3,
			reset_token_hash = $4, reset_token_expires_at = $5, consumed_at = $6
		WHERE id = $1
	`

	tag, err := r.db.Exec(ctx, q,
		f.ID, f.OTPVerifiedAt, f.OTPAttempts, f.ResetTokenHash, f.ResetTokenExpiresAt, f.ConsumedAt,
	)
	if err != nil {
		return fmt.Errorf("postgres: update password reset flow: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return passwordreset.ErrNotFound
	}

	return nil
}

func (r *PasswordResetFlowRepository) scanOne(ctx context.Context, q string, arg any) (*passwordreset.PasswordResetFlow, error) {
	var f passwordreset.PasswordResetFlow

	err := r.db.QueryRow(ctx, q, arg).Scan(
		&f.ID, &f.UserID, &f.FlowTokenHash, &f.OTPVerifiedAt, &f.OTPAttempts,
		&f.ResetTokenHash, &f.ResetTokenExpiresAt, &f.ExpiresAt, &f.ConsumedAt, &f.CreatedAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, passwordreset.ErrNotFound
		}
		return nil, fmt.Errorf("postgres: get password reset flow: %w", err)
	}

	return &f, nil
}
