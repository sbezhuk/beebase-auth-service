package passwordreset

import "context"

// Repository is the port through which the application persists and
// retrieves password reset flows.
type Repository interface {
	Create(ctx context.Context, f *PasswordResetFlow) error
	GetByFlowTokenHash(ctx context.Context, hash string) (*PasswordResetFlow, error)
	GetByResetTokenHash(ctx context.Context, hash string) (*PasswordResetFlow, error)
	// Update persists f's current field values in full. Returns
	// ErrNotFound if f.ID doesn't match an existing row.
	Update(ctx context.Context, f *PasswordResetFlow) error
}
