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
