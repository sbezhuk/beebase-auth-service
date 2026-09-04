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
	UserID                uuid.UUID
	Email                 string
	AccessToken           string
	AccessTokenExpiresAt  time.Time
	RefreshToken          string
	RefreshTokenExpiresAt time.Time
}

// UpdateProfileInput is the input to Service.UpdateProfile. FirstName and
// LastName are always replaced (PUT semantics: there is no partial-update
// case for them). Avatar is nil when the caller didn't mention avatar at
// all, leaving the current one untouched; a non-nil Avatar makes the
// change explicit - see AvatarChange.
type UpdateProfileInput struct {
	FirstName string
	LastName  string
	Avatar    *AvatarChange
}

// AvatarChange is UpdateProfileInput's explicit avatar mutation: a nil
// MediaID removes the current avatar, a populated one replaces it with
// that already-uploaded media id (ownership verified via MediaClient
// before it's persisted).
type AvatarChange struct {
	MediaID *uuid.UUID
}

// RegisterResult is the result of Service.Register: a pending TOTP setup
// challenge, not yet a session - registration isn't complete until
// SetupVerifyOTP succeeds.
type RegisterResult struct {
	UserID     uuid.UUID
	SetupToken string
	OtpauthURI string
	Secret     string
	ExpiresAt  time.Time
}

// LoginStatus distinguishes the two non-session outcomes Login can return
// once credentials have already checked out.
type LoginStatus string

const (
	// LoginStatusOTPRequired means credentials were valid and the account
	// already has 2FA enabled: an OTP is now required to complete login.
	LoginStatusOTPRequired LoginStatus = "otp_required"
	// LoginStatusTOTPSetupRequired means credentials were valid but the
	// account has no enabled TOTP credential yet (setup was never started
	// or never finished): a fresh setup challenge has been issued.
	LoginStatusTOTPSetupRequired LoginStatus = "totp_setup_required"
)

// LoginResult is the result of Service.Login. Exactly one of
// ChallengeToken or {SetupToken, OtpauthURI, Secret} is populated,
// matching Status.
type LoginResult struct {
	Status LoginStatus

	// ChallengeToken is set iff Status is LoginStatusOTPRequired.
	ChallengeToken string

	// SetupToken, OtpauthURI, and Secret are set iff Status is
	// LoginStatusTOTPSetupRequired.
	SetupToken string
	OtpauthURI string
	Secret     string

	ExpiresAt time.Time
}

// ChangePasswordInput is the input to Service.ChangePassword.
type ChangePasswordInput struct {
	CurrentPassword string
	NewPassword     string
	OTP             string
}

// PasswordResetRequestResult is the result of Service.RequestPasswordReset.
// Its shape never varies with whether the account was eligible - see
// Service.RequestPasswordReset.
type PasswordResetRequestResult struct {
	FlowToken string
	ExpiresAt time.Time
}

// PasswordResetOTPResult is the result of Service.VerifyPasswordResetOTP.
type PasswordResetOTPResult struct {
	ResetToken string
	ExpiresAt  time.Time
}
