package auth

import (
	"time"

	"github.com/google/uuid"
)

// RegisterInput is the input to Service.Register.
type RegisterInput struct {
	Email    string
	Password string
}

// LoginInput is the input to Service.Login.
type LoginInput struct {
	Email    string
	Password string
}

// Session is the result of any use case that establishes or renews a
// user's session: Register, Login, and Refresh all return one.
type Session struct {
	UserID               uuid.UUID
	Email                string
	AccessToken          string
	AccessTokenExpiresAt time.Time
	RefreshToken         string
}
