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
	AccessToken           string       `json:"accessToken"`
	AccessTokenExpiresAt  int64        `json:"accessTokenExpiresAt"`
	RefreshTokenExpiresAt int64        `json:"refreshTokenExpiresAt"`
	User                  UserResponse `json:"user"`
}

// UserResponse is the public representation of a user.
type UserResponse struct {
	ID        uuid.UUID `json:"id"`
	Email     string    `json:"email"`
	CreatedAt time.Time `json:"createdAt"`
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

// TOTPSetupResponse is returned whenever a TOTP setup challenge has been
// issued: by Register, and by Login when the account's 2FA setup was never
// completed. Secret and OtpauthURI are only ever returned at this one
// point - once a credential is enabled, neither is ever exposed again by
// any other endpoint.
type TOTPSetupResponse struct {
	Status     string `json:"status"`
	SetupToken string `json:"setupToken"`
	OtpauthURI string `json:"otpauthUri"`
	Secret     string `json:"secret"`
	ExpiresAt  int64  `json:"expiresAt"`
}

func newTOTPSetupResponseFromRegister(r *appauth.RegisterResult) TOTPSetupResponse {
	return TOTPSetupResponse{
		Status:     string(appauth.LoginStatusTOTPSetupRequired),
		SetupToken: r.SetupToken,
		OtpauthURI: r.OtpauthURI,
		Secret:     r.Secret,
		ExpiresAt:  r.ExpiresAt.Unix(),
	}
}

func newTOTPSetupResponseFromLogin(r *appauth.LoginResult) TOTPSetupResponse {
	return TOTPSetupResponse{
		Status:     string(r.Status),
		SetupToken: r.SetupToken,
		OtpauthURI: r.OtpauthURI,
		Secret:     r.Secret,
		ExpiresAt:  r.ExpiresAt.Unix(),
	}
}

// LoginOTPRequiredResponse is returned by Login when the account already
// has 2FA enabled: ChallengeToken, plus a valid OTP, must be presented to
// LoginVerifyOTP to obtain a session.
type LoginOTPRequiredResponse struct {
	Status         string `json:"status"`
	ChallengeToken string `json:"challengeToken"`
	ExpiresAt      int64  `json:"expiresAt"`
}

func newLoginOTPRequiredResponse(r *appauth.LoginResult) LoginOTPRequiredResponse {
	return LoginOTPRequiredResponse{
		Status:         string(r.Status),
		ChallengeToken: r.ChallengeToken,
		ExpiresAt:      r.ExpiresAt.Unix(),
	}
}

// PasswordResetRequestedResponse is returned by RequestPasswordReset. Its
// shape never varies with whether the account was eligible for recovery -
// see application/auth.Service.RequestPasswordReset.
type PasswordResetRequestedResponse struct {
	FlowToken string `json:"flowToken"`
	ExpiresAt int64  `json:"expiresAt"`
}

func newPasswordResetRequestedResponse(r *appauth.PasswordResetRequestResult) PasswordResetRequestedResponse {
	return PasswordResetRequestedResponse{FlowToken: r.FlowToken, ExpiresAt: r.ExpiresAt.Unix()}
}

// PasswordResetOTPVerifiedResponse is returned by VerifyPasswordResetOTP:
// ResetToken must be presented to ConfirmPasswordReset to actually change
// the password.
type PasswordResetOTPVerifiedResponse struct {
	ResetToken string `json:"resetToken"`
	ExpiresAt  int64  `json:"expiresAt"`
}

func newPasswordResetOTPVerifiedResponse(r *appauth.PasswordResetOTPResult) PasswordResetOTPVerifiedResponse {
	return PasswordResetOTPVerifiedResponse{ResetToken: r.ResetToken, ExpiresAt: r.ExpiresAt.Unix()}
}
