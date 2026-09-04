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

	// FirstName and LastName are the profile's display name. Both default
	// to "" for an account that has never set them - there is no "unset"
	// distinct from "empty" for either field.
	FirstName string
	LastName  string
	// AvatarMediaID is the id of an already-uploaded media-service file,
	// or nil if the profile has no avatar. media-service is the sole
	// source of truth for the file itself; this is only a reference,
	// verified against media-service before it's ever written here (see
	// application/auth.Service.UpdateProfile).
	AvatarMediaID *uuid.UUID

	CreatedAt time.Time
	UpdatedAt time.Time
}

// New constructs a User with a freshly generated ID and timestamps set to
// now. Callers are expected to have already hashed the password. The
// profile fields (name, avatar) start empty; they're set later through
// UpdateProfile.
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

// UpdateProfile replaces the profile's editable fields and refreshes
// UpdatedAt. Email and PasswordHash are untouched - this method only ever
// covers the profile surface (see application/auth.Service.UpdateProfile).
func (u *User) UpdateProfile(firstName, lastName string, avatarMediaID *uuid.UUID) {
	u.FirstName = firstName
	u.LastName = lastName
	u.AvatarMediaID = avatarMediaID
	u.UpdatedAt = time.Now().UTC()
}

// ChangePassword replaces the account's password hash and refreshes
// UpdatedAt. Callers are expected to have already verified the caller
// knows the current password and, where required, a valid OTP - this
// method only ever covers the mutation itself (see
// application/auth.Service.ChangePassword and ConfirmPasswordReset).
func (u *User) ChangePassword(newHash string) {
	u.PasswordHash = newHash
	u.UpdatedAt = time.Now().UTC()
}
