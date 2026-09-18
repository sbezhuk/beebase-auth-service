package auth

import (
	"encoding/json"
	"net/http"
	"net/mail"
	"strings"
	"unicode"

	"github.com/sbezhuk/beebase-common/httpx"
)

const minPasswordLength = 8

// passwordSpecialChars are the characters accepted as "special characters"
// by validatePassword. Kept narrow and explicit (rather than "anything
// non-alphanumeric") so the rule is easy to state to users and to mirror
// exactly on the Flutter client.
const passwordSpecialChars = "!@#$%^&*()_+-=[]{}|;:,.<>?"

const otpLength = 6

// Field validation error codes. Each is a stable key a client can map to a
// localized message; the field carrying no error is simply absent from the
// response's "fields" map.
const (
	CodeEmailRequired              = "email_required"
	CodeEmailInvalid               = "email_invalid"
	CodePasswordRequired           = "password_required"
	CodePasswordTooShort           = "password_too_short"
	CodePasswordMissingDigit       = "password_missing_digit"
	CodePasswordMissingSpecialChar = "password_missing_special_char"

	CodeOTPRequired             = "otp_required"
	CodeOTPInvalidFormat        = "otp_invalid_format"
	CodeSetupTokenRequired      = "setup_token_required"
	CodeChallengeTokenRequired  = "challenge_token_required"
	CodeCurrentPasswordRequired = "current_password_required"
	CodeConfirmPasswordMismatch = "confirm_password_mismatch"
	CodeFlowTokenRequired       = "flow_token_required"
	CodeResetTokenRequired      = "reset_token_required"
)

// validatable is implemented by every request DTO in this package.
// Validate returns a map of field name to error code, empty if valid.
type validatable interface {
	Validate() map[string]string
}

// decodeAndValidate decodes the request body into dst and validates it,
// writing an appropriate error response and returning false if either step
// fails.
func decodeAndValidate(w http.ResponseWriter, r *http.Request, dst validatable) bool {
	defer func() { _ = r.Body.Close() }()

	if err := json.NewDecoder(r.Body).Decode(dst); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, httpx.CodeInvalidBody, "request body must be valid JSON")
		return false
	}

	if fields := dst.Validate(); len(fields) > 0 {
		httpx.WriteValidationError(w, fields)
		return false
	}

	return true
}

// RegisterRequest is the body of POST /auth/register.
type RegisterRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

func (r *RegisterRequest) Validate() map[string]string {
	fields := map[string]string{}
	if code := validateEmail(r.Email); code != "" {
		fields["email"] = code
	}
	if code := validatePassword(r.Password); code != "" {
		fields["password"] = code
	}
	return fields
}

// LoginRequest is the body of POST /auth/login.
type LoginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

func (r *LoginRequest) Validate() map[string]string {
	fields := map[string]string{}
	if code := validateEmail(r.Email); code != "" {
		fields["email"] = code
	}
	if r.Password == "" {
		fields["password"] = CodePasswordRequired
	}
	return fields
}

func validateEmail(email string) string {
	if strings.TrimSpace(email) == "" {
		return CodeEmailRequired
	}
	if _, err := mail.ParseAddress(email); err != nil {
		return CodeEmailInvalid
	}
	return ""
}

// validatePassword enforces the password strength policy applied whenever a
// new password is created or set (registration, password reset, change
// password). It is deliberately not used by LoginRequest.Validate: existing
// users must still be able to sign in with passwords that predate this
// policy.
func validatePassword(password string) string {
	if len(password) < minPasswordLength {
		return CodePasswordTooShort
	}
	if !containsDigit(password) {
		return CodePasswordMissingDigit
	}
	if !strings.ContainsAny(password, passwordSpecialChars) {
		return CodePasswordMissingSpecialChar
	}
	return ""
}

func containsDigit(s string) bool {
	for _, r := range s {
		if unicode.IsDigit(r) {
			return true
		}
	}
	return false
}

// validateOTP checks that code has the shape of a Google Authenticator
// TOTP code (exactly 6 digits) before it's ever passed to the service -
// so a malformed code never consumes an OTP-lockout attempt.
func validateOTP(code string) string {
	if code == "" {
		return CodeOTPRequired
	}
	if len(code) != otpLength {
		return CodeOTPInvalidFormat
	}
	for _, r := range code {
		if r < '0' || r > '9' {
			return CodeOTPInvalidFormat
		}
	}
	return ""
}

// SetupVerifyRequest is the body of POST /auth/2fa/setup/verify.
type SetupVerifyRequest struct {
	SetupToken string `json:"setupToken"`
	OTP        string `json:"otp"`
}

func (r *SetupVerifyRequest) Validate() map[string]string {
	fields := map[string]string{}
	if strings.TrimSpace(r.SetupToken) == "" {
		fields["setupToken"] = CodeSetupTokenRequired
	}
	if code := validateOTP(r.OTP); code != "" {
		fields["otp"] = code
	}
	return fields
}

// LoginVerifyOTPRequest is the body of POST /auth/login/verify-otp.
type LoginVerifyOTPRequest struct {
	ChallengeToken string `json:"challengeToken"`
	OTP            string `json:"otp"`
}

func (r *LoginVerifyOTPRequest) Validate() map[string]string {
	fields := map[string]string{}
	if strings.TrimSpace(r.ChallengeToken) == "" {
		fields["challengeToken"] = CodeChallengeTokenRequired
	}
	if code := validateOTP(r.OTP); code != "" {
		fields["otp"] = code
	}
	return fields
}

// ChangePasswordRequest is the body of POST /auth/change-password.
type ChangePasswordRequest struct {
	CurrentPassword string `json:"currentPassword"`
	NewPassword     string `json:"newPassword"`
	OTP             string `json:"otp"`
}

func (r *ChangePasswordRequest) Validate() map[string]string {
	fields := map[string]string{}
	if r.CurrentPassword == "" {
		fields["currentPassword"] = CodeCurrentPasswordRequired
	}
	if code := validatePassword(r.NewPassword); code != "" {
		fields["newPassword"] = code
	}
	if code := validateOTP(r.OTP); code != "" {
		fields["otp"] = code
	}
	return fields
}

// PasswordResetRequestRequest is the body of POST /auth/password-reset/request.
type PasswordResetRequestRequest struct {
	Email string `json:"email"`
}

func (r *PasswordResetRequestRequest) Validate() map[string]string {
	fields := map[string]string{}
	if code := validateEmail(r.Email); code != "" {
		fields["email"] = code
	}
	return fields
}

// PasswordResetVerifyOTPRequest is the body of POST
// /auth/password-reset/verify-otp.
type PasswordResetVerifyOTPRequest struct {
	FlowToken string `json:"flowToken"`
	OTP       string `json:"otp"`
}

func (r *PasswordResetVerifyOTPRequest) Validate() map[string]string {
	fields := map[string]string{}
	if strings.TrimSpace(r.FlowToken) == "" {
		fields["flowToken"] = CodeFlowTokenRequired
	}
	if code := validateOTP(r.OTP); code != "" {
		fields["otp"] = code
	}
	return fields
}

// PasswordResetConfirmRequest is the body of POST
// /auth/password-reset/confirm.
type PasswordResetConfirmRequest struct {
	ResetToken      string `json:"resetToken"`
	NewPassword     string `json:"newPassword"`
	ConfirmPassword string `json:"confirmPassword"`
}

func (r *PasswordResetConfirmRequest) Validate() map[string]string {
	fields := map[string]string{}
	if strings.TrimSpace(r.ResetToken) == "" {
		fields["resetToken"] = CodeResetTokenRequired
	}
	if code := validatePassword(r.NewPassword); code != "" {
		fields["newPassword"] = code
	}
	if r.NewPassword != r.ConfirmPassword {
		fields["confirmPassword"] = CodeConfirmPasswordMismatch
	}
	return fields
}
