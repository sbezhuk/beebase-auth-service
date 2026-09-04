package user

import (
	"context"

	"github.com/google/uuid"
)

// Repository is the port through which the application persists and
// retrieves users. It is deliberately specific to User, not a generic
// CRUD interface, so each method can carry its own meaning and error
// semantics (e.g. GetByEmail returning ErrNotFound).
type Repository interface {
	Create(ctx context.Context, u *User) error
	GetByEmail(ctx context.Context, email string) (*User, error)
	GetByID(ctx context.Context, id uuid.UUID) (*User, error)
	// Update persists u's current field values (profile fields and
	// UpdatedAt). Email and PasswordHash are never changed through this
	// path. Returns ErrNotFound if u.ID doesn't match an existing row.
	Update(ctx context.Context, u *User) error
	// UpdatePassword replaces id's password hash. This is the only path
	// that may ever change PasswordHash - Update (profile fields) never
	// does. Returns ErrNotFound if id doesn't match an existing row.
	UpdatePassword(ctx context.Context, id uuid.UUID, passwordHash string) error
}
