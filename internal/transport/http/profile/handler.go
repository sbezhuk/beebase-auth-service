// Package profile holds the HTTP handlers for the authenticated user's own
// profile: reading it and editing its name/avatar. Handlers stay thin:
// they decode/validate the request, pull the authenticated user's ID (and,
// for Update, their raw access token, forwarded to media-service to
// verify a newly-referenced avatar) from the request, call into the auth
// application service, and map the result (or error) to a response. No
// business logic or repository access happens here.
package profile

import (
	"errors"
	"log/slog"
	"net/http"
	"strings"

	"github.com/google/uuid"

	appauth "github.com/sbezhuk/beebase-auth-service/internal/application/auth"
	"github.com/sbezhuk/beebase-auth-service/internal/domain/user"
	httpmw "github.com/sbezhuk/beebase-common/authmw"
	"github.com/sbezhuk/beebase-common/httpx"
)

// Error codes for profile failures, returned as the top-level
// "error.code". Each is a stable key a client can map to a localized
// message.
const (
	CodeUserNotFound   = "user_not_found"
	CodeAvatarNotFound = "avatar_not_found"
)

// Handler exposes the profile HTTP endpoints. Every method requires the
// request to have already passed through httpmw.RequireAuth.
type Handler struct {
	service *appauth.Service
	log     *slog.Logger
}

// NewHandler returns a Handler backed by service.
func NewHandler(service *appauth.Service, log *slog.Logger) *Handler {
	return &Handler{service: service, log: log}
}

// Get handles GET /profile.
func (h *Handler) Get(w http.ResponseWriter, r *http.Request) {
	userID, ok := h.requireUserID(w, r)
	if !ok {
		return
	}

	u, err := h.service.CurrentUser(r.Context(), userID)
	if err != nil {
		h.writeServiceError(w, err)
		return
	}

	httpx.WriteJSON(w, http.StatusOK, newResponse(u))
}

// Update handles PUT /profile. The endpoint only ever operates on the
// caller's own profile - userID comes from the verified access token, not
// from the request body, so there is no way to target another user's
// profile.
func (h *Handler) Update(w http.ResponseWriter, r *http.Request) {
	userID, token, ok := h.requireAuth(w, r)
	if !ok {
		return
	}

	var req UpdateProfileRequest
	if !decodeAndValidate(w, r, &req) {
		return
	}

	var avatar *appauth.AvatarChange
	if req.Avatar != nil {
		if *req.Avatar == "" {
			avatar = &appauth.AvatarChange{}
		} else {
			id, _ := uuid.Parse(*req.Avatar) // already validated by req.Validate
			avatar = &appauth.AvatarChange{MediaID: &id}
		}
	}

	updated, err := h.service.UpdateProfile(r.Context(), userID, token, appauth.UpdateProfileInput{
		FirstName: strings.TrimSpace(req.FirstName),
		LastName:  strings.TrimSpace(req.LastName),
		Avatar:    avatar,
	})
	if err != nil {
		h.writeServiceError(w, err)
		return
	}

	httpx.WriteJSON(w, http.StatusOK, newResponse(updated))
}

// Delete handles DELETE /profile. It permanently deletes the caller's own
// account and everything owned by it (every apiary, hive, inspection, and
// their media), and revokes every session belonging to it. The account to
// delete is always the caller's own - userID comes from the verified
// access token, never from the request - so there is no way to target
// another user's account.
func (h *Handler) Delete(w http.ResponseWriter, r *http.Request) {
	userID, token, ok := h.requireAuth(w, r)
	if !ok {
		return
	}

	if err := h.service.DeleteAccount(r.Context(), userID, token); err != nil {
		h.writeServiceError(w, err)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) requireUserID(w http.ResponseWriter, r *http.Request) (uuid.UUID, bool) {
	userID, ok := httpmw.UserIDFromContext(r.Context())
	if !ok {
		httpx.WriteError(w, http.StatusUnauthorized, httpmw.CodeMissingAuthorization, "missing authentication")
		return uuid.Nil, false
	}
	return userID, true
}

// requireAuth returns the authenticated user's ID alongside their raw
// access token (read back off the request's own Authorization header,
// which RequireAuth already validated), forwarded to media-service to
// verify ownership of a newly-referenced avatar id.
func (h *Handler) requireAuth(w http.ResponseWriter, r *http.Request) (uuid.UUID, string, bool) {
	userID, ok := h.requireUserID(w, r)
	if !ok {
		return uuid.Nil, "", false
	}

	const prefix = "Bearer "
	token := strings.TrimPrefix(r.Header.Get("Authorization"), prefix)

	return userID, token, true
}

func (h *Handler) writeServiceError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, user.ErrNotFound):
		httpx.WriteError(w, http.StatusNotFound, CodeUserNotFound, "user not found")
	case errors.Is(err, appauth.ErrAvatarNotFound):
		httpx.WriteValidationError(w, map[string]string{"avatar": CodeAvatarNotFound})
	default:
		httpx.WriteInternalError(w, h.log, err)
	}
}
