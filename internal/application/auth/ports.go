package auth

import (
	"time"

	"github.com/google/uuid"
)

// PasswordHasher hashes and verifies user passwords. It's a port because
// the algorithm and its cost are an infrastructure concern the service
// shouldn't be coupled to.
type PasswordHasher interface {
	Hash(plainPassword string) (string, error)
	Verify(hash, plainPassword string) error
}

// AccessTokenIssuer issues signed access tokens for authenticated users.
// It's a port so the service doesn't depend on JWT specifically.
type AccessTokenIssuer interface {
	Issue(userID uuid.UUID) (token string, expiresAt time.Time, err error)
}
