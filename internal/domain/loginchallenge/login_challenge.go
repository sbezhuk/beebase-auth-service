// Package loginchallenge holds the LoginChallenge entity - the OTP-required
// gate between a successful password check and full session issuance - and
// the port through which the application persists and retrieves it.
package loginchallenge

import (
	"time"

	"github.com/google/uuid"
)

// LoginChallenge is issued when a password check succeeds against a
// 2FA-enabled account. The client must present the matching raw token plus
// a valid OTP to LoginVerifyOTP before a session is ever issued; the
// challenge itself never grants access.
type LoginChallenge struct {
	ID         uuid.UUID
	UserID     uuid.UUID
	TokenHash  string
	ExpiresAt  time.Time
	CreatedAt  time.Time
	ConsumedAt *time.Time
}

// New constructs a LoginChallenge for userID, valid for ttl, storing only
// the given hash of the opaque challenge token (never the token itself).
func New(userID uuid.UUID, tokenHash string, ttl time.Duration) *LoginChallenge {
	now := time.Now().UTC()
	return &LoginChallenge{
		ID:        uuid.New(),
		UserID:    userID,
		TokenHash: tokenHash,
		ExpiresAt: now.Add(ttl),
		CreatedAt: now,
	}
}

// IsExpired reports whether the challenge's validity window has passed.
func (c *LoginChallenge) IsExpired() bool {
	return time.Now().UTC().After(c.ExpiresAt)
}

// IsConsumed reports whether the challenge has already been used.
func (c *LoginChallenge) IsConsumed() bool {
	return c.ConsumedAt != nil
}
