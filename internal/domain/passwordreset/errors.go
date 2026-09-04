package passwordreset

import "errors"

// ErrNotFound is returned when no password reset flow matches the given
// lookup.
var ErrNotFound = errors.New("password reset flow not found")
