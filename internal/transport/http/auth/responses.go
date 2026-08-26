package auth

import (
	"time"

	"github.com/google/uuid"

	appauth "github.com/sbezhuk/beebase-auth-service/internal/application/auth"
	"github.com/sbezhuk/beebase-auth-service/internal/domain/user"
)

// SessionResponse is returned by register, login, and refresh: it carries
// a freshly issued access token and the refresh token's expiry. The
// refresh token itself is never included here — it's set as an HttpOnly
// cookie instead, so it's never exposed to client-side JavaScript. Its
// expiry is plain metadata, not a secret, so it's safe to return here for
// a client that wants to know when it'll need to re-authenticate.
//
// Both expiry fields are Unix timestamps (seconds), matching the "exp"
// claim already inside the access token JWT itself.
type SessionResponse struct {
	AccessToken           string       `json:"access_token"`
	AccessTokenExpiresAt  int64        `json:"access_token_expires_at"`
	RefreshTokenExpiresAt int64        `json:"refresh_token_expires_at"`
	User                  UserResponse `json:"user"`
}

// UserResponse is the public representation of a user.
type UserResponse struct {
	ID        uuid.UUID `json:"id"`
	Email     string    `json:"email"`
	CreatedAt time.Time `json:"created_at"`
}

func newSessionResponse(s *appauth.Session) SessionResponse {
	return SessionResponse{
		AccessToken:           s.AccessToken,
		AccessTokenExpiresAt:  s.AccessTokenExpiresAt.Unix(),
		RefreshTokenExpiresAt: s.RefreshTokenExpiresAt.Unix(),
		User: UserResponse{
			ID:    s.UserID,
			Email: s.Email,
		},
	}
}

func newUserResponse(u *user.User) UserResponse {
	return UserResponse{ID: u.ID, Email: u.Email, CreatedAt: u.CreatedAt}
}
