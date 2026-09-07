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
	// Used to enforce a single active session per user (every new session
	// issued kills whatever came before it), when a revoked token is
	// replayed (signals the token chain may have been stolen, so the whole
	// session family is killed rather than just the one token), and as a
	// defense-in-depth measure on other credential-security events like a
	// password change.
	RevokeAllForUser(ctx context.Context, userID uuid.UUID) error
}
