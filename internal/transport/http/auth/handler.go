// Package auth holds the HTTP handlers for authentication. Handlers stay
// thin: they decode and validate the request, call into the application
// service, and map the result (or error) to a response. No business logic
// or repository access happens here.
package auth

import (
	"errors"
	"log/slog"
	"net/http"

	appauth "github.com/sbezhuk/beebase-auth-service/internal/application/auth"
	"github.com/sbezhuk/beebase-auth-service/internal/domain/user"
	httpmw "github.com/sbezhuk/beebase-common/authmw"

	"github.com/sbezhuk/beebase-common/httpx"
)

// Error codes for authentication failures, returned as the top-level
// "error.code". Each is a stable key a client can map to a localized
// message.
const (
	CodeEmailTaken          = "email_taken"
	CodeUserNotFound        = "user_not_found"
	CodeInvalidCredentials  = "invalid_credentials"
	CodeInvalidRefreshToken = "invalid_refresh_token"
)

// refreshTokenCookieName is the cookie the refresh token travels in. It's
// never exposed in a JSON response body, so client-side JavaScript can
// never read it.
const refreshTokenCookieName = "refresh_token"

// refreshTokenCookiePath scopes the cookie to the auth endpoints that
// actually need it, so it isn't attached to every other request the
// browser makes through the gateway.
const refreshTokenCookiePath = "/api/v1/auth"

// Handler exposes the authentication HTTP endpoints.
type Handler struct {
	service *appauth.Service
	log     *slog.Logger
	cookie  httpx.CookieOptions
}

// NewHandler returns a Handler backed by service. cookie configures how
// the refresh token cookie is scoped and secured (domain, Secure,
// SameSite).
func NewHandler(service *appauth.Service, log *slog.Logger, cookie httpx.CookieOptions) *Handler {
	return &Handler{service: service, log: log, cookie: cookie}
}

// setRefreshCookie attaches session's refresh token as an HttpOnly cookie.
func (h *Handler) setRefreshCookie(w http.ResponseWriter, session *appauth.Session) {
	httpx.SetCookie(w, refreshTokenCookieName, session.RefreshToken, refreshTokenCookiePath, session.RefreshTokenExpiresAt, h.cookie)
}

// clearRefreshCookie expires the refresh token cookie, e.g. on logout.
func (h *Handler) clearRefreshCookie(w http.ResponseWriter) {
	httpx.ClearCookie(w, refreshTokenCookieName, refreshTokenCookiePath, h.cookie)
}

// refreshTokenFromCookie reads the raw refresh token out of the request
// cookie, writing an unauthorized response and returning false if it's
// missing.
func (h *Handler) refreshTokenFromCookie(w http.ResponseWriter, r *http.Request) (string, bool) {
	c, err := r.Cookie(refreshTokenCookieName)
	if err != nil || c.Value == "" {
		httpx.WriteError(w, http.StatusUnauthorized, CodeInvalidRefreshToken, "invalid or expired refresh token")
		return "", false
	}
	return c.Value, true
}

// Register handles POST /auth/register.
func (h *Handler) Register(w http.ResponseWriter, r *http.Request) {
	var req RegisterRequest
	if !decodeAndValidate(w, r, &req) {
		return
	}

	session, err := h.service.Register(r.Context(), appauth.RegisterInput{
		Email:    req.Email,
		Password: req.Password,
	})
	if err != nil {
		h.writeServiceError(w, err)
		return
	}

	h.setRefreshCookie(w, session)
	httpx.WriteJSON(w, http.StatusCreated, newSessionResponse(session))
}

// Login handles POST /auth/login.
func (h *Handler) Login(w http.ResponseWriter, r *http.Request) {
	var req LoginRequest
	if !decodeAndValidate(w, r, &req) {
		return
	}

	session, err := h.service.Login(r.Context(), appauth.LoginInput{
		Email:    req.Email,
		Password: req.Password,
	})
	if err != nil {
		h.writeServiceError(w, err)
		return
	}

	h.setRefreshCookie(w, session)
	httpx.WriteJSON(w, http.StatusOK, newSessionResponse(session))
}

// Refresh handles POST /auth/refresh.
func (h *Handler) Refresh(w http.ResponseWriter, r *http.Request) {
	rawToken, ok := h.refreshTokenFromCookie(w, r)
	if !ok {
		return
	}

	session, err := h.service.Refresh(r.Context(), rawToken)
	if err != nil {
		h.writeServiceError(w, err)
		return
	}

	h.setRefreshCookie(w, session)
	httpx.WriteJSON(w, http.StatusOK, newSessionResponse(session))
}

// Logout handles POST /auth/logout.
func (h *Handler) Logout(w http.ResponseWriter, r *http.Request) {
	rawToken, ok := h.refreshTokenFromCookie(w, r)
	if !ok {
		return
	}

	if err := h.service.Logout(r.Context(), rawToken); err != nil {
		h.writeServiceError(w, err)
		return
	}

	h.clearRefreshCookie(w)
	w.WriteHeader(http.StatusNoContent)
}

// Me handles GET /auth/me. It must run behind middleware.RequireAuth.
func (h *Handler) Me(w http.ResponseWriter, r *http.Request) {
	userID, ok := httpmw.UserIDFromContext(r.Context())
	if !ok {
		httpx.WriteError(w, http.StatusUnauthorized, httpmw.CodeMissingAuthorization, "missing authentication")
		return
	}

	u, err := h.service.CurrentUser(r.Context(), userID)
	if err != nil {
		h.writeServiceError(w, err)
		return
	}

	httpx.WriteJSON(w, http.StatusOK, newUserResponse(u))
}

func (h *Handler) writeServiceError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, user.ErrEmailTaken):
		httpx.WriteError(w, http.StatusConflict, CodeEmailTaken, "an account with this email already exists")
	case errors.Is(err, user.ErrNotFound):
		httpx.WriteError(w, http.StatusNotFound, CodeUserNotFound, "user not found")
	case errors.Is(err, appauth.ErrInvalidCredentials):
		httpx.WriteError(w, http.StatusUnauthorized, CodeInvalidCredentials, "invalid email or password")
	case errors.Is(err, appauth.ErrInvalidRefreshToken):
		httpx.WriteError(w, http.StatusUnauthorized, CodeInvalidRefreshToken, "invalid or expired refresh token")
	default:
		httpx.WriteInternalError(w, h.log, err)
	}
}
