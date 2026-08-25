// Package token holds the RefreshToken entity and its persistence port.
// The raw opaque token handed to a client never appears here: this package
// only ever sees and stores its hash, so a compromised database dump can't
// be replayed as a live session.
package token

import (
	"time"

	"github.com/google/uuid"
)

// RefreshToken is one link in a session's rotation chain. Each successful
// refresh revokes the presented token and issues a new one; presenting an
// already-revoked token is treated as a signal the token was stolen.
type RefreshToken struct {
	ID        uuid.UUID
	UserID    uuid.UUID
	TokenHash string
	ExpiresAt time.Time
	CreatedAt time.Time
	RevokedAt *time.Time
}

// New constructs a RefreshToken for userID, valid for ttl, storing only the
// given hash of the opaque token (never the token itself).
func New(userID uuid.UUID, tokenHash string, ttl time.Duration) *RefreshToken {
	now := time.Now().UTC()
	return &RefreshToken{
		ID:        uuid.New(),
		UserID:    userID,
		TokenHash: tokenHash,
		ExpiresAt: now.Add(ttl),
		CreatedAt: now,
	}
}

// IsExpired reports whether the token's validity window has passed.
func (t *RefreshToken) IsExpired() bool {
	return time.Now().UTC().After(t.ExpiresAt)
}

// IsRevoked reports whether the token has already been used or explicitly
// revoked (e.g. via logout).
func (t *RefreshToken) IsRevoked() bool {
	return t.RevokedAt != nil
}
