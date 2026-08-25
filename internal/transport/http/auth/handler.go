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

// Handler exposes the authentication HTTP endpoints.
type Handler struct {
	service *appauth.Service
	log     *slog.Logger
}

// NewHandler returns a Handler backed by service.
func NewHandler(service *appauth.Service, log *slog.Logger) *Handler {
	return &Handler{service: service, log: log}
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

	httpx.WriteJSON(w, http.StatusOK, newSessionResponse(session))
}

// Refresh handles POST /auth/refresh.
func (h *Handler) Refresh(w http.ResponseWriter, r *http.Request) {
	var req RefreshRequest
	if !decodeAndValidate(w, r, &req) {
		return
	}

	session, err := h.service.Refresh(r.Context(), req.RefreshToken)
	if err != nil {
		h.writeServiceError(w, err)
		return
	}

	httpx.WriteJSON(w, http.StatusOK, newSessionResponse(session))
}

// Logout handles POST /auth/logout.
func (h *Handler) Logout(w http.ResponseWriter, r *http.Request) {
	var req RefreshRequest
	if !decodeAndValidate(w, r, &req) {
		return
	}

	if err := h.service.Logout(r.Context(), req.RefreshToken); err != nil {
		h.writeServiceError(w, err)
		return
	}

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
