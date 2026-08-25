package auth

import (
	"time"

	"github.com/google/uuid"

	appauth "github.com/sbezhuk/beebase-auth-service/internal/application/auth"
	"github.com/sbezhuk/beebase-auth-service/internal/domain/user"
)

// SessionResponse is returned by register, login, and refresh: it carries
// a freshly issued access/refresh token pair.
type SessionResponse struct {
	AccessToken          string       `json:"access_token"`
	AccessTokenExpiresAt time.Time    `json:"access_token_expires_at"`
	RefreshToken         string       `json:"refresh_token"`
	User                 UserResponse `json:"user"`
}

// UserResponse is the public representation of a user.
type UserResponse struct {
	ID        uuid.UUID `json:"id"`
	Email     string    `json:"email"`
	CreatedAt time.Time `json:"created_at"`
}

func newSessionResponse(s *appauth.Session) SessionResponse {
	return SessionResponse{
		AccessToken:          s.AccessToken,
		AccessTokenExpiresAt: s.AccessTokenExpiresAt,
		RefreshToken:         s.RefreshToken,
		User: UserResponse{
			ID:    s.UserID,
			Email: s.Email,
		},
	}
}

func newUserResponse(u *user.User) UserResponse {
	return UserResponse{ID: u.ID, Email: u.Email, CreatedAt: u.CreatedAt}
}
