package profile

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/google/uuid"

	"github.com/sbezhuk/beebase-common/httpx"
)

const (
	maxFirstNameLength = 100
	maxLastNameLength  = 100
)

// Field validation error codes. Each is a stable key a client can map to a
// localized message; the field carrying no error is simply absent from the
// response's "fields" map.
const (
	CodeFirstNameRequired = "first_name_required"
	CodeFirstNameTooLong  = "first_name_too_long"
	CodeLastNameRequired  = "last_name_required"
	CodeLastNameTooLong   = "last_name_too_long"
	CodeAvatarInvalid     = "avatar_invalid"
)

// decodeAndValidate decodes the request body into dst and validates it,
// writing an appropriate error response and returning false if either step
// fails.
func decodeAndValidate(w http.ResponseWriter, r *http.Request, dst *UpdateProfileRequest) bool {
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

// UpdateProfileRequest is the body of PUT /profile.
type UpdateProfileRequest struct {
	FirstName string `json:"firstName"`
	LastName  string `json:"lastName"`
	// Avatar, when present (including as an explicit JSON null), is the
	// caller's desired avatar: an empty string removes the current
	// avatar, a valid media id replaces it. Omitting the field entirely
	// leaves the current avatar untouched. Go's json package already
	// distinguishes "absent" (nil pointer) from "present" (non-nil,
	// possibly pointing to ""), which is exactly the distinction this
	// needs; JSON null and an absent key are treated the same (both leave
	// the avatar untouched), matching hive-service's Images field.
	Avatar *string `json:"avatar"`
}

func (r *UpdateProfileRequest) Validate() map[string]string {
	fields := map[string]string{}

	name := strings.TrimSpace(r.FirstName)
	switch {
	case name == "":
		fields["firstName"] = CodeFirstNameRequired
	case len(name) > maxFirstNameLength:
		fields["firstName"] = CodeFirstNameTooLong
	}

	last := strings.TrimSpace(r.LastName)
	switch {
	case last == "":
		fields["lastName"] = CodeLastNameRequired
	case len(last) > maxLastNameLength:
		fields["lastName"] = CodeLastNameTooLong
	}

	if r.Avatar != nil && *r.Avatar != "" {
		if _, err := uuid.Parse(*r.Avatar); err != nil {
			fields["avatar"] = CodeAvatarInvalid
		}
	}

	return fields
}
