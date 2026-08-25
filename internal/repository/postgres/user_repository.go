package postgres

import (
	"context"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/sbezhuk/beebase-auth-service/internal/domain/user"
)

// uniqueViolationCode is PostgreSQL's SQLSTATE for a unique constraint
// violation. See https://www.postgresql.org/docs/current/errcodes-appendix.html
const uniqueViolationCode = "23505"

// UserRepository implements domain/user.Repository against PostgreSQL.
type UserRepository struct {
	db Querier
}

// NewUserRepository returns a UserRepository backed by db.
func NewUserRepository(db Querier) *UserRepository {
	return &UserRepository{db: db}
}

func (r *UserRepository) Create(ctx context.Context, u *user.User) error {
	const q = `
		INSERT INTO users (id, email, password_hash, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5)
	`

	_, err := r.db.Exec(ctx, q, u.ID, u.Email, u.PasswordHash, u.CreatedAt, u.UpdatedAt)
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == uniqueViolationCode {
			return user.ErrEmailTaken
		}
		return fmt.Errorf("postgres: create user: %w", err)
	}

	return nil
}

func (r *UserRepository) GetByEmail(ctx context.Context, email string) (*user.User, error) {
	const q = `
		SELECT id, email, password_hash, created_at, updated_at
		FROM users
		WHERE email = $1
	`
	return r.scanOne(ctx, q, email)
}

func (r *UserRepository) GetByID(ctx context.Context, id uuid.UUID) (*user.User, error) {
	const q = `
		SELECT id, email, password_hash, created_at, updated_at
		FROM users
		WHERE id = $1
	`
	return r.scanOne(ctx, q, id)
}

func (r *UserRepository) scanOne(ctx context.Context, q string, arg any) (*user.User, error) {
	var u user.User

	err := r.db.QueryRow(ctx, q, arg).Scan(&u.ID, &u.Email, &u.PasswordHash, &u.CreatedAt, &u.UpdatedAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, user.ErrNotFound
		}
		return nil, fmt.Errorf("postgres: get user: %w", err)
	}

	return &u, nil
}
