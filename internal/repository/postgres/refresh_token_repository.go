package postgres

import (
	"context"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/sbezhuk/BeeBase-Server/internal/domain/token"
)

// RefreshTokenRepository implements domain/token.Repository against
// PostgreSQL.
type RefreshTokenRepository struct {
	db Querier
}

// NewRefreshTokenRepository returns a RefreshTokenRepository backed by db.
func NewRefreshTokenRepository(db Querier) *RefreshTokenRepository {
	return &RefreshTokenRepository{db: db}
}

func (r *RefreshTokenRepository) Create(ctx context.Context, t *token.RefreshToken) error {
	const q = `
		INSERT INTO refresh_tokens (id, user_id, token_hash, expires_at, created_at, revoked_at)
		VALUES ($1, $2, $3, $4, $5, $6)
	`

	_, err := r.db.Exec(ctx, q, t.ID, t.UserID, t.TokenHash, t.ExpiresAt, t.CreatedAt, t.RevokedAt)
	if err != nil {
		return fmt.Errorf("postgres: create refresh token: %w", err)
	}

	return nil
}

func (r *RefreshTokenRepository) GetByHash(ctx context.Context, hash string) (*token.RefreshToken, error) {
	const q = `
		SELECT id, user_id, token_hash, expires_at, created_at, revoked_at
		FROM refresh_tokens
		WHERE token_hash = $1
	`

	var t token.RefreshToken

	err := r.db.QueryRow(ctx, q, hash).Scan(&t.ID, &t.UserID, &t.TokenHash, &t.ExpiresAt, &t.CreatedAt, &t.RevokedAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, token.ErrNotFound
		}
		return nil, fmt.Errorf("postgres: get refresh token: %w", err)
	}

	return &t, nil
}

func (r *RefreshTokenRepository) Revoke(ctx context.Context, id uuid.UUID) error {
	const q = `UPDATE refresh_tokens SET revoked_at = now() WHERE id = $1 AND revoked_at IS NULL`

	if _, err := r.db.Exec(ctx, q, id); err != nil {
		return fmt.Errorf("postgres: revoke refresh token: %w", err)
	}

	return nil
}

func (r *RefreshTokenRepository) RevokeAllForUser(ctx context.Context, userID uuid.UUID) error {
	const q = `UPDATE refresh_tokens SET revoked_at = now() WHERE user_id = $1 AND revoked_at IS NULL`

	if _, err := r.db.Exec(ctx, q, userID); err != nil {
		return fmt.Errorf("postgres: revoke all refresh tokens: %w", err)
	}

	return nil
}
