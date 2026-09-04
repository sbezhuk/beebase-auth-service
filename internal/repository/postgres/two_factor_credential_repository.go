package postgres

import (
	"context"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/sbezhuk/beebase-auth-service/internal/domain/totp"
)

// TwoFactorCredentialRepository implements domain/totp.Repository against
// PostgreSQL.
type TwoFactorCredentialRepository struct {
	db Querier
}

// NewTwoFactorCredentialRepository returns a TwoFactorCredentialRepository
// backed by db.
func NewTwoFactorCredentialRepository(db Querier) *TwoFactorCredentialRepository {
	return &TwoFactorCredentialRepository{db: db}
}

func (r *TwoFactorCredentialRepository) Create(ctx context.Context, c *totp.Credential) error {
	const q = `
		INSERT INTO two_factor_credentials (
			user_id, secret_encrypted, enabled_at,
			setup_token_hash, setup_token_expires_at,
			failed_attempts, locked_until, created_at, updated_at
		)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
	`

	_, err := r.db.Exec(ctx, q,
		c.UserID, c.SecretEncrypted, c.EnabledAt,
		c.SetupTokenHash, c.SetupTokenExpiresAt,
		c.FailedAttempts, c.LockedUntil, c.CreatedAt, c.UpdatedAt,
	)
	if err != nil {
		return fmt.Errorf("postgres: create totp credential: %w", err)
	}

	return nil
}

func (r *TwoFactorCredentialRepository) GetByUserID(ctx context.Context, userID uuid.UUID) (*totp.Credential, error) {
	const q = `
		SELECT user_id, secret_encrypted, enabled_at,
			setup_token_hash, setup_token_expires_at,
			failed_attempts, locked_until, created_at, updated_at
		FROM two_factor_credentials
		WHERE user_id = $1
	`
	return r.scanOne(ctx, q, userID)
}

func (r *TwoFactorCredentialRepository) GetBySetupTokenHash(ctx context.Context, hash string) (*totp.Credential, error) {
	const q = `
		SELECT user_id, secret_encrypted, enabled_at,
			setup_token_hash, setup_token_expires_at,
			failed_attempts, locked_until, created_at, updated_at
		FROM two_factor_credentials
		WHERE setup_token_hash = $1
	`
	return r.scanOne(ctx, q, hash)
}

func (r *TwoFactorCredentialRepository) Update(ctx context.Context, c *totp.Credential) error {
	const q = `
		UPDATE two_factor_credentials
		SET secret_encrypted = $2, enabled_at = $3,
			setup_token_hash = $4, setup_token_expires_at = $5,
			failed_attempts = $6, locked_until = $7, updated_at = $8
		WHERE user_id = $1
	`

	tag, err := r.db.Exec(ctx, q,
		c.UserID, c.SecretEncrypted, c.EnabledAt,
		c.SetupTokenHash, c.SetupTokenExpiresAt,
		c.FailedAttempts, c.LockedUntil, c.UpdatedAt,
	)
	if err != nil {
		return fmt.Errorf("postgres: update totp credential: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return totp.ErrNotFound
	}

	return nil
}

func (r *TwoFactorCredentialRepository) scanOne(ctx context.Context, q string, arg any) (*totp.Credential, error) {
	var c totp.Credential

	err := r.db.QueryRow(ctx, q, arg).Scan(
		&c.UserID, &c.SecretEncrypted, &c.EnabledAt,
		&c.SetupTokenHash, &c.SetupTokenExpiresAt,
		&c.FailedAttempts, &c.LockedUntil, &c.CreatedAt, &c.UpdatedAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, totp.ErrNotFound
		}
		return nil, fmt.Errorf("postgres: get totp credential: %w", err)
	}

	return &c, nil
}
