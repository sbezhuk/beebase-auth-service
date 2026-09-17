package auth

import (
	"testing"
	"time"

	"github.com/google/uuid"

	appauth "github.com/sbezhuk/beebase-auth-service/internal/application/auth"
)

func TestNewSessionResponseIncludesUserCreatedAt(t *testing.T) {
	createdAt := time.Date(2026, time.September, 17, 12, 34, 56, 0, time.UTC)
	session := &appauth.Session{
		UserID: uuid.New(),
		Email:  "user@example.com",
		// The response must preserve the timestamp loaded from the user row.
		CreatedAt: createdAt,
	}

	response := newSessionResponse(session)

	if !response.User.CreatedAt.Equal(createdAt) {
		t.Fatalf("user.createdAt = %v, want %v", response.User.CreatedAt, createdAt)
	}
}
