package user

import "errors"

var (
	// ErrNotFound is returned when no user matches the given lookup.
	ErrNotFound = errors.New("user not found")

	// ErrEmailTaken is returned when registering an email that is already
	// associated with an account. No two users may share an email.
	ErrEmailTaken = errors.New("email already registered")
)
