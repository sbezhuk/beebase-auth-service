// Package middleware holds chi middleware specific to this project (as
// opposed to chi's own generic middleware package).
package middleware

import (
	"context"
	"net/http"
	"strings"

	"github.com/google/uuid"

	"github.com/sbezhuk/BeeBase-Server/internal/transport/http/httpx"
)

type contextKey int

const userIDContextKey contextKey = iota

// Error codes for authentication failures. Kept distinct so a client can
// tell "you were never logged in" (CodeMissingAuthorization) apart from
// "your session ended" (CodeInvalidAccessToken) and localize accordingly.
const (
	CodeMissingAuthorization = "missing_authorization"
	CodeInvalidAccessToken   = "invalid_access_token"
)

// AccessTokenParser verifies an access token string and returns the user
// ID it was issued for.
type AccessTokenParser interface {
	Parse(token string) (uuid.UUID, error)
}

// RequireAuth returns middleware that rejects requests without a valid
// "Authorization: Bearer <token>" header, and otherwise makes the
// authenticated user's ID available via UserIDFromContext.
func RequireAuth(parser AccessTokenParser) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			token, ok := bearerToken(r)
			if !ok {
				httpx.WriteError(w, http.StatusUnauthorized, CodeMissingAuthorization, "missing or invalid authorization header")
				return
			}

			userID, err := parser.Parse(token)
			if err != nil {
				httpx.WriteError(w, http.StatusUnauthorized, CodeInvalidAccessToken, "invalid or expired access token")
				return
			}

			ctx := context.WithValue(r.Context(), userIDContextKey, userID)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// UserIDFromContext returns the user ID stored by RequireAuth, if any.
func UserIDFromContext(ctx context.Context) (uuid.UUID, bool) {
	id, ok := ctx.Value(userIDContextKey).(uuid.UUID)
	return id, ok
}

func bearerToken(r *http.Request) (string, bool) {
	const prefix = "Bearer "

	header := r.Header.Get("Authorization")
	if !strings.HasPrefix(header, prefix) {
		return "", false
	}

	token := strings.TrimPrefix(header, prefix)
	if token == "" {
		return "", false
	}

	return token, true
}
