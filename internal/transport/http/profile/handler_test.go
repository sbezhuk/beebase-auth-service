package profile

import (
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	appauth "github.com/sbezhuk/beebase-auth-service/internal/application/auth"
)

func TestHandlerWriteServiceErrorOTPInvalidIsBadRequest(t *testing.T) {
	h := &Handler{log: slog.Default()}
	rec := httptest.NewRecorder()

	h.writeServiceError(rec, appauth.ErrOTPInvalid)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusBadRequest)
	}
}
