// Package httpx holds small HTTP response helpers shared by every handler
// package, so response encoding and error shape stay consistent across
// features without a heavier shared framework.
package httpx

import (
	"encoding/json"
	"net/http"
)

// WriteJSON writes body as a JSON response with the given status code.
func WriteJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}
