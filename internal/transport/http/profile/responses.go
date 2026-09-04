package profile

import (
	"github.com/google/uuid"

	"github.com/sbezhuk/beebase-auth-service/internal/domain/user"
)

// Response is the public representation of a user's profile.
type Response struct {
	ID        uuid.UUID  `json:"id"`
	Email     string     `json:"email"`
	FirstName string     `json:"firstName"`
	LastName  string     `json:"lastName"`
	Avatar    *uuid.UUID `json:"avatar"`
}

func newResponse(u *user.User) Response {
	return Response{
		ID:        u.ID,
		Email:     u.Email,
		FirstName: u.FirstName,
		LastName:  u.LastName,
		Avatar:    u.AvatarMediaID,
	}
}
