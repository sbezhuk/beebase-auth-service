package auth

import (
	"encoding/json"
	"net/http"
	"net/mail"
	"strings"

	"github.com/sbezhuk/beebase-common/httpx"
)

const minPasswordLength = 8

// Field validation error codes. Each is a stable key a client can map to a
// localized message; the field carrying no error is simply absent from the
// response's "fields" map.
const (
	CodeEmailRequired    = "email_required"
	CodeEmailInvalid     = "email_invalid"
	CodePasswordRequired = "password_required"
	CodePasswordTooShort = "password_too_short"
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

func validatePassword(password string) string {
	if len(password) < minPasswordLength {
		return CodePasswordTooShort
	}
	return ""
}
