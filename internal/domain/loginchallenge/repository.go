package loginchallenge

import (
	"context"

	"github.com/google/uuid"
)

// Repository is the port through which the application persists and
// retrieves login challenges.
type Repository interface {
	Create(ctx context.Context, c *LoginChallenge) error
	GetByHash(ctx context.Context, hash string) (*LoginChallenge, error)
	// Consume marks the challenge identified by id as used. It is
	// idempotent: consuming an already-consumed challenge is not an error,
	// since the desired end state (it can no longer be used) already
	// holds.
	Consume(ctx context.Context, id uuid.UUID) error
}
