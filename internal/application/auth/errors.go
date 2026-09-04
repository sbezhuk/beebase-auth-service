package auth

import "errors"

// ErrInvalidCredentials covers both an unknown email and a wrong password:
// the two are never distinguished to a caller, so a login attempt can't be
// used to enumerate which emails are registered.
var ErrInvalidCredentials = errors.New("invalid email or password")

// ErrInvalidRefreshToken covers a refresh token that is unknown, expired,
// or already revoked. As with ErrInvalidCredentials, these are collapsed
// into one error so a caller can't distinguish them.
var ErrInvalidRefreshToken = errors.New("invalid refresh token")

// ErrAvatarNotFound is returned by UpdateProfile when the given avatar
// media id doesn't belong to the caller (unknown, deleted, or someone
// else's - indistinguishable, by the same non-leaking convention
// user.ErrNotFound already follows).
var ErrAvatarNotFound = errors.New("avatar not found")

// ErrOTPInvalid is returned when a submitted 6-digit code doesn't validate
// against the relevant TOTP secret.
var ErrOTPInvalid = errors.New("invalid otp code")

// ErrOTPLocked is returned once an OTP-verification attempt cap has been
// exhausted - either the account-level lockout (setup-verify,
// login-verify-otp, change-password) or a single password-reset flow's own
// cap. Both cases return this same error so a caller can never tell which
// kind of lockout occurred.
var ErrOTPLocked = errors.New("too many failed otp attempts")

// ErrSetupTokenInvalid covers a TOTP setup token that is unknown or
// expired.
var ErrSetupTokenInvalid = errors.New("invalid or expired setup token")

// ErrChallengeInvalid covers a login challenge token that is unknown,
// expired, or already consumed.
var ErrChallengeInvalid = errors.New("invalid or expired login challenge")

// ErrCurrentPasswordInvalid is returned by ChangePassword when the
// supplied current password doesn't match the account's password.
var ErrCurrentPasswordInvalid = errors.New("current password is incorrect")

// ErrPasswordResetFlowInvalid covers a password-reset flow token that is
// unknown, expired, consumed, or already past the OTP-verify step.
var ErrPasswordResetFlowInvalid = errors.New("invalid or expired password reset flow")

// ErrPasswordResetTokenInvalid covers a password-reset token that is
// unknown, expired, consumed, or not yet backed by a successful OTP
// verification - this is what makes skipping the OTP step structurally
// impossible, not just a policy choice.
var ErrPasswordResetTokenInvalid = errors.New("invalid or expired password reset token")
