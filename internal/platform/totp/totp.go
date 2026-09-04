// Package totp generates and validates RFC 6238 TOTP codes compatible with
// Google Authenticator, wrapping github.com/pquerna/otp. This is not a
// swappable port (like application/auth.PasswordHasher) - there is no
// anticipated alternative to standard TOTP - so it's called directly, the
// same way platform/tokenhash is.
package totp

import (
	"fmt"
	"time"

	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
)

// codeSkew allows a code from one period (30s) before or after the current
// one to still validate, tolerating clock drift between the server and the
// user's authenticator app.
const codeSkew = 1

// GenerateSecret creates a new random TOTP secret and its standard
// otpauth:// URI (for a client to render as a QR code or accept as manual
// entry). issuer is the label shown in the authenticator app (e.g.
// "BeeBase"); accountName identifies the account within it (the user's
// email). The returned secret is base32-encoded, matching what Validate
// expects.
func GenerateSecret(issuer, accountName string) (secretBase32, otpauthURI string, err error) {
	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      issuer,
		AccountName: accountName,
	})
	if err != nil {
		return "", "", fmt.Errorf("totp: generate secret: %w", err)
	}
	return key.Secret(), key.URL(), nil
}

// Validate reports whether code is a currently-valid TOTP for secretBase32
// (base32-encoded, as returned by GenerateSecret), allowing for a small
// window of clock skew.
func Validate(code, secretBase32 string) bool {
	ok, err := totp.ValidateCustom(code, secretBase32, time.Now().UTC(), totp.ValidateOpts{
		Period:    30,
		Skew:      codeSkew,
		Digits:    otp.DigitsSix,
		Algorithm: otp.AlgorithmSHA1,
	})
	if err != nil {
		return false
	}
	return ok
}
