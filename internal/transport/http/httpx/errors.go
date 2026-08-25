package httpx

import (
	"log/slog"
	"net/http"
)

// Generic error codes shared across every feature. Each is a stable key a
// client can map to a localized message; "message" is a human-readable
// fallback for logs and manual debugging, not meant to be shown to users.
const (
	CodeValidationError = "validation_error"
	CodeInvalidBody     = "invalid_body"
	CodeInternalError   = "internal_error"
)

type errorBody struct {
	Error errorDetail `json:"error"`
}

type errorDetail struct {
	Code    string            `json:"code"`
	Message string            `json:"message"`
	Fields  map[string]string `json:"fields,omitempty"`
}

// WriteError writes a {"error": {"code", "message"}} response.
func WriteError(w http.ResponseWriter, status int, code, message string) {
	WriteJSON(w, status, errorBody{Error: errorDetail{Code: code, Message: message}})
}

// WriteValidationError writes a 400 response carrying the fields that
// failed validation, keyed by field name. Each value is itself a stable
// error code (e.g. "email_invalid"), not a human-readable message.
func WriteValidationError(w http.ResponseWriter, fields map[string]string) {
	WriteJSON(w, http.StatusBadRequest, errorBody{Error: errorDetail{
		Code:    CodeValidationError,
		Message: "request validation failed",
		Fields:  fields,
	}})
}

// WriteInternalError logs the real error server-side and writes a generic
// 500 response, so internals never leak to the client over the wire.
func WriteInternalError(w http.ResponseWriter, log *slog.Logger, err error) {
	log.Error("internal server error", "error", err)
	WriteError(w, http.StatusInternalServerError, CodeInternalError, "something went wrong")
}
