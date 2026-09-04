package loginchallenge

import "errors"

// ErrNotFound is returned when no login challenge matches the given hash.
var ErrNotFound = errors.New("login challenge not found")
