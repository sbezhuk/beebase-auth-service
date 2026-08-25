package token

import (
	"context"

	"github.com/google/uuid"
)

// Repository is the port through which the application persists and
// retrieves refresh tokens.
type Repository interface {
	Create(ctx context.Context, t *RefreshToken) error
	GetByHash(ctx context.Context, hash string) (*RefreshToken, error)
	Revoke(ctx context.Context, id uuid.UUID) error
	// RevokeAllForUser revokes every non-revoked refresh token for userID.
	// Used when a revoked token is replayed, which signals the token chain
	// may have been stolen: the whole session family is killed rather than
	// just the one token.
	RevokeAllForUser(ctx context.Context, userID uuid.UUID) error
}
