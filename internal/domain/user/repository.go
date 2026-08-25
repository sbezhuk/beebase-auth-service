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
}
