// Package user holds the User entity and the port through which the rest
// of the application persists and retrieves it. It has no dependency on
// HTTP, PostgreSQL, or any other infrastructure concern.
package user

import (
	"time"

	"github.com/google/uuid"
)

// User is a registered account.
type User struct {
	ID           uuid.UUID
	Email        string
	PasswordHash string
	CreatedAt    time.Time
	UpdatedAt    time.Time
}

// New constructs a User with a freshly generated ID and timestamps set to
// now. Callers are expected to have already hashed the password.
func New(email, passwordHash string) *User {
	now := time.Now().UTC()
	return &User{
		ID:           uuid.New(),
		Email:        email,
		PasswordHash: passwordHash,
		CreatedAt:    now,
		UpdatedAt:    now,
	}
}
