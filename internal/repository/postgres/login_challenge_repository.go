package postgres

import (
	"context"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/sbezhuk/beebase-auth-service/internal/domain/loginchallenge"
)

// LoginChallengeRepository implements domain/loginchallenge.Repository
// against PostgreSQL.
type LoginChallengeRepository struct {
	db Querier
}

// NewLoginChallengeRepository returns a LoginChallengeRepository backed by
// db.
func NewLoginChallengeRepository(db Querier) *LoginChallengeRepository {
	return &LoginChallengeRepository{db: db}
}

func (r *LoginChallengeRepository) Create(ctx context.Context, c *loginchallenge.LoginChallenge) error {
	const q = `
		INSERT INTO login_challenges (id, user_id, token_hash, expires_at, created_at, consumed_at)
		VALUES ($1, $2, $3, $4, $5, $6)
	`

	_, err := r.db.Exec(ctx, q, c.ID, c.UserID, c.TokenHash, c.ExpiresAt, c.CreatedAt, c.ConsumedAt)
	if err != nil {
		return fmt.Errorf("postgres: create login challenge: %w", err)
	}

	return nil
}

func (r *LoginChallengeRepository) GetByHash(ctx context.Context, hash string) (*loginchallenge.LoginChallenge, error) {
	const q = `
		SELECT id, user_id, token_hash, expires_at, created_at, consumed_at
		FROM login_challenges
		WHERE token_hash = $1
	`

	var c loginchallenge.LoginChallenge

	err := r.db.QueryRow(ctx, q, hash).Scan(&c.ID, &c.UserID, &c.TokenHash, &c.ExpiresAt, &c.CreatedAt, &c.ConsumedAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, loginchallenge.ErrNotFound
		}
		return nil, fmt.Errorf("postgres: get login challenge: %w", err)
	}

	return &c, nil
}

func (r *LoginChallengeRepository) Consume(ctx context.Context, id uuid.UUID) error {
	const q = `UPDATE login_challenges SET consumed_at = now() WHERE id = $1 AND consumed_at IS NULL`

	if _, err := r.db.Exec(ctx, q, id); err != nil {
		return fmt.Errorf("postgres: consume login challenge: %w", err)
	}

	return nil
}
