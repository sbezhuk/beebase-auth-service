package totp

import (
	"context"

	"github.com/google/uuid"
)

// Repository is the port through which the application persists and
// retrieves TOTP credentials.
type Repository interface {
	Create(ctx context.Context, c *Credential) error
	GetByUserID(ctx context.Context, userID uuid.UUID) (*Credential, error)
	// GetBySetupTokenHash looks up the credential whose pending setup
	// challenge matches hash. Used by the setup-verify endpoint, which is
	// reached with only a setup token - never a user id.
	GetBySetupTokenHash(ctx context.Context, hash string) (*Credential, error)
	// Update persists c's current field values in full. Returns
	// ErrNotFound if c.UserID doesn't match an existing row.
	Update(ctx context.Context, c *Credential) error
}
