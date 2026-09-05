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
	"github.com/pquerna/otp/hotp"
	gotptotp "github.com/pquerna/otp/totp"
)

// period is how many seconds each TOTP code is valid for.
const period = 30

// forwardSkew tolerates a code for the period immediately after the
// current one, for a user's authenticator whose clock runs slightly fast.
// There is deliberately no backward equivalent: once the server's clock
// has moved into a new period, a code from the period that just ended must
// stop working immediately, not linger for an extra period - see BEEB-41,
// where a code was still accepted a couple of seconds after a new one had
// already been generated. Combined with the anti-replay check described on
// ValidateAt, a code is usable for at most the single moment it's actually
// current (plus this one-sided allowance), never after.
const forwardSkew = 1

// GenerateSecret creates a new random TOTP secret and its standard
// otpauth:// URI (for a client to render as a QR code or accept as manual
// entry). issuer is the label shown in the authenticator app (e.g.
// "BeeBase"); accountName identifies the account within it (the user's
// email). The returned secret is base32-encoded, matching what Validate
// expects.
func GenerateSecret(issuer, accountName string) (secretBase32, otpauthURI string, err error) {
	key, err := gotptotp.Generate(gotptotp.GenerateOpts{
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
//
// Validate alone does not prevent replay: a code accepted once remains
// accepted for anyone who resubmits it until it falls outside the skew
// window. Callers that need single-use semantics (every caller that gates
// an authentication decision on this package) must use ValidateAt instead,
// and enforce its matchedCounter against the credential's
// domain/totp.Credential.IsCodeConsumed / MarkCodeUsed.
func Validate(code, secretBase32 string) bool {
	ok, _ := ValidateAt(code, secretBase32, time.Now().UTC())
	return ok
}

// ValidateAt reports whether code is a valid TOTP for secretBase32 at time
// t: the current period's code, or the very next period's (forwardSkew).
// A code from a period that has already ended is never valid, no matter
// how recently it ended. When ok, matchedCounter is the RFC 6238 time-step
// counter the code validated against.
//
// Callers MUST reject a code whose matchedCounter is less than or equal to
// the counter of a code this credential has already accepted (see
// domain/totp.Credential.IsCodeConsumed) and, on acceptance, record it
// (Credential.MarkCodeUsed/RecordSuccess) - otherwise a code an attacker
// captured (e.g. by shoulder-surfing or intercepting it in transit) stays
// usable for a second attempt even within its own single valid period,
// which RFC 6238 §5.2 requires servers to prohibit.
func ValidateAt(code, secretBase32 string, t time.Time) (ok bool, matchedCounter int64) {
	current := t.Unix() / period

	for i := int64(0); i <= forwardSkew; i++ {
		counter := current + i
		match, err := hotp.ValidateCustom(code, uint64(counter), secretBase32, hotp.ValidateOpts{
			Digits:    otp.DigitsSix,
			Algorithm: otp.AlgorithmSHA1,
		})
		if err != nil {
			continue
		}
		if match {
			return true, counter
		}
	}

	return false, 0
}
