package auth

import (
	"context"
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

// MediaClient is auth-service's dependency on media-service, used solely
// to verify a caller's ownership of a newly-referenced avatar media id
// before persisting it. media-service has no notion of "profile avatar" -
// it only knows which files belong to which uploader - so this remains
// the only source of truth for "does this media id exist and belong to
// me". Mirrors the same port other services (e.g. hive-service) already
// declare against media-service.
type MediaClient interface {
	// VerifyOwnership confirms every id in ids belongs to whoever
	// presented accessToken, by asking media-service directly. Returns
	// ErrAvatarNotFound if any id doesn't (unknown, deleted, or someone
	// else's - indistinguishable, by the same non-leaking convention
	// user.ErrNotFound already follows).
	VerifyOwnership(ctx context.Context, accessToken string, ids []uuid.UUID) error
	// DeleteAllByUser hard-deletes every media item belonging to whoever
	// presented accessToken. Used only by Service.DeleteAccount, as the
	// final sweep for media never referenced by any apiary/hive/
	// inspection - e.g. the profile avatar, or an upload that was never
	// attached to anything - which the apiary-service cascade
	// (ApiaryCascadeDeleter) would never reach on its own.
	DeleteAllByUser(ctx context.Context, accessToken string) error
}

// ApiaryCascadeDeleter deletes every apiary belonging to whoever presented
// accessToken - and, transitively, their hives, inspections, and media -
// in apiary-service, as part of cascading an account delete. It's a port
// because apiaries live in a different service with its own database.
type ApiaryCascadeDeleter interface {
	DeleteAllMine(ctx context.Context, accessToken string) error
}
