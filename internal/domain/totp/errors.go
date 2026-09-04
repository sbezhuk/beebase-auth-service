package totp

import "errors"

// ErrNotFound is returned when no credential matches the given lookup.
var ErrNotFound = errors.New("totp credential not found")
