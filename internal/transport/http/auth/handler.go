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

	CodeOTPInvalid                = "otp_invalid"
	CodeOTPLocked                 = "otp_locked"
	CodeSetupTokenInvalid         = "totp_setup_token_invalid"
	CodeChallengeInvalid          = "login_challenge_invalid"
	CodeCurrentPasswordInvalid    = "current_password_invalid"
	CodePasswordResetFlowInvalid  = "password_reset_flow_invalid"
	CodePasswordResetTokenInvalid = "password_reset_token_invalid"
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

// Register handles POST /auth/register. It creates the account and issues
// a TOTP setup challenge - registration is not complete, and no session is
// issued, until SetupVerifyOTP succeeds.
func (h *Handler) Register(w http.ResponseWriter, r *http.Request) {
	var req RegisterRequest
	if !decodeAndValidate(w, r, &req) {
		return
	}

	result, err := h.service.Register(r.Context(), appauth.RegisterInput{
		Email:    req.Email,
		Password: req.Password,
	})
	if err != nil {
		h.writeServiceError(w, err)
		return
	}

	httpx.WriteJSON(w, http.StatusCreated, newTOTPSetupResponseFromRegister(result))
}

// Login handles POST /auth/login. It never issues a session directly: on
// valid credentials it returns either an OTP challenge (2FA already
// enabled - see LoginVerifyOTP) or a TOTP setup challenge (2FA never
// completed - see SetupVerifyOTP).
func (h *Handler) Login(w http.ResponseWriter, r *http.Request) {
	var req LoginRequest
	if !decodeAndValidate(w, r, &req) {
		return
	}

	result, err := h.service.Login(r.Context(), appauth.LoginInput{
		Email:    req.Email,
		Password: req.Password,
	})
	if err != nil {
		h.writeServiceError(w, err)
		return
	}

	if result.Status == appauth.LoginStatusOTPRequired {
		httpx.WriteJSON(w, http.StatusOK, newLoginOTPRequiredResponse(result))
		return
	}
	httpx.WriteJSON(w, http.StatusOK, newTOTPSetupResponseFromLogin(result))
}

// SetupVerifyOTP handles POST /auth/2fa/setup/verify. On success it
// completes the pending TOTP setup (from Register or a Login-triggered
// setup) and issues a full session.
func (h *Handler) SetupVerifyOTP(w http.ResponseWriter, r *http.Request) {
	var req SetupVerifyRequest
	if !decodeAndValidate(w, r, &req) {
		return
	}

	session, err := h.service.SetupVerifyOTP(r.Context(), req.SetupToken, req.OTP)
	if err != nil {
		h.writeServiceError(w, err)
		return
	}

	h.setRefreshCookie(w, session)
	httpx.WriteJSON(w, http.StatusOK, newSessionResponse(session))
}

// LoginVerifyOTP handles POST /auth/login/verify-otp. On success it
// completes a login begun by Login and issues a full session.
func (h *Handler) LoginVerifyOTP(w http.ResponseWriter, r *http.Request) {
	var req LoginVerifyOTPRequest
	if !decodeAndValidate(w, r, &req) {
		return
	}

	session, err := h.service.LoginVerifyOTP(r.Context(), req.ChallengeToken, req.OTP)
	if err != nil {
		h.writeServiceError(w, err)
		return
	}

	h.setRefreshCookie(w, session)
	httpx.WriteJSON(w, http.StatusOK, newSessionResponse(session))
}

// ChangePassword handles POST /auth/change-password. It must run behind
// middleware.RequireAuth. Both the current password and a valid OTP are
// required; the password is left unchanged if either check fails.
func (h *Handler) ChangePassword(w http.ResponseWriter, r *http.Request) {
	userID, ok := httpmw.UserIDFromContext(r.Context())
	if !ok {
		httpx.WriteError(w, http.StatusUnauthorized, httpmw.CodeMissingAuthorization, "missing authentication")
		return
	}

	var req ChangePasswordRequest
	if !decodeAndValidate(w, r, &req) {
		return
	}

	err := h.service.ChangePassword(r.Context(), userID, appauth.ChangePasswordInput{
		CurrentPassword: req.CurrentPassword,
		NewPassword:     req.NewPassword,
		OTP:             req.OTP,
	})
	if err != nil {
		h.writeServiceError(w, err)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// RequestPasswordReset handles POST /auth/password-reset/request. It
// always succeeds with an identical response shape, whether or not the
// email belongs to an eligible account, so a caller can never use this
// endpoint to enumerate registered emails.
func (h *Handler) RequestPasswordReset(w http.ResponseWriter, r *http.Request) {
	var req PasswordResetRequestRequest
	if !decodeAndValidate(w, r, &req) {
		return
	}

	result, err := h.service.RequestPasswordReset(r.Context(), req.Email)
	if err != nil {
		h.writeServiceError(w, err)
		return
	}

	httpx.WriteJSON(w, http.StatusOK, newPasswordResetRequestedResponse(result))
}

// VerifyPasswordResetOTP handles POST /auth/password-reset/verify-otp.
func (h *Handler) VerifyPasswordResetOTP(w http.ResponseWriter, r *http.Request) {
	var req PasswordResetVerifyOTPRequest
	if !decodeAndValidate(w, r, &req) {
		return
	}

	result, err := h.service.VerifyPasswordResetOTP(r.Context(), req.FlowToken, req.OTP)
	if err != nil {
		h.writeServiceError(w, err)
		return
	}

	httpx.WriteJSON(w, http.StatusOK, newPasswordResetOTPVerifiedResponse(result))
}

// ConfirmPasswordReset handles POST /auth/password-reset/confirm. It can
// never succeed without a prior successful VerifyPasswordResetOTP against
// the same flow - see application/auth.Service.ConfirmPasswordReset.
func (h *Handler) ConfirmPasswordReset(w http.ResponseWriter, r *http.Request) {
	var req PasswordResetConfirmRequest
	if !decodeAndValidate(w, r, &req) {
		return
	}

	if err := h.service.ConfirmPasswordReset(r.Context(), req.ResetToken, req.NewPassword); err != nil {
		h.writeServiceError(w, err)
		return
	}

	w.WriteHeader(http.StatusNoContent)
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
	case errors.Is(err, appauth.ErrOTPInvalid):
		httpx.WriteError(w, http.StatusUnauthorized, CodeOTPInvalid, "invalid otp code")
	case errors.Is(err, appauth.ErrOTPLocked):
		httpx.WriteError(w, http.StatusTooManyRequests, CodeOTPLocked, "too many failed otp attempts")
	case errors.Is(err, appauth.ErrSetupTokenInvalid):
		httpx.WriteError(w, http.StatusUnauthorized, CodeSetupTokenInvalid, "invalid or expired setup token")
	case errors.Is(err, appauth.ErrChallengeInvalid):
		httpx.WriteError(w, http.StatusUnauthorized, CodeChallengeInvalid, "invalid or expired login challenge")
	case errors.Is(err, appauth.ErrCurrentPasswordInvalid):
		httpx.WriteError(w, http.StatusUnauthorized, CodeCurrentPasswordInvalid, "current password is incorrect")
	case errors.Is(err, appauth.ErrPasswordResetFlowInvalid):
		httpx.WriteError(w, http.StatusBadRequest, CodePasswordResetFlowInvalid, "invalid or expired password reset flow")
	case errors.Is(err, appauth.ErrPasswordResetTokenInvalid):
		httpx.WriteError(w, http.StatusBadRequest, CodePasswordResetTokenInvalid, "invalid or expired password reset token")
	default:
		httpx.WriteInternalError(w, h.log, err)
	}
}
