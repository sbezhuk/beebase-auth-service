// Package totp holds the Credential entity - a user's TOTP (Google
// Authenticator) enrollment - and the port through which the application
// persists and retrieves it. It has no dependency on HTTP, PostgreSQL, or
// any TOTP/crypto library; those live in platform/totp and
// platform/totpsecret.
package totp

import (
	"time"

	"github.com/google/uuid"
)

// Credential is one user's TOTP enrollment. It is created the moment setup
// begins (at registration, or when an existing user without an enabled
// credential logs in) and only ever becomes usable for login once Enable
// has been called.
type Credential struct {
	UserID uuid.UUID

	// SecretEncrypted is the AES-GCM ciphertext of the TOTP secret (nonce
	// prepended, see platform/totpsecret). Never held or logged as
	// plaintext outside the brief window verifyOTP decrypts it in memory.
	SecretEncrypted []byte

	// EnabledAt is nil until the first successful setup-verify. A nil
	// EnabledAt means the account cannot log in yet - setup is incomplete.
	EnabledAt *time.Time

	// SetupTokenHash/SetupTokenExpiresAt identify the pending setup
	// challenge, if any. Both are nil once no setup is pending.
	SetupTokenHash      *string
	SetupTokenExpiresAt *time.Time

	// FailedAttempts/LockedUntil are the account-level OTP lockout,
	// shared by every flow that already proves password knowledge
	// (setup-verify, login-verify-otp, change-password). Forgot-password
	// deliberately does NOT touch these - see passwordreset.PasswordResetFlow.
	FailedAttempts int
	LockedUntil    *time.Time

	// LastUsedCounter is the RFC 6238 time-step counter of the most
	// recently accepted TOTP code, or nil if none has ever been accepted.
	// This is the standard TOTP anti-replay requirement (RFC 6238 §5.2):
	// without it, a code captured by an attacker stays usable for as long
	// as the validation skew tolerates it, even after the legitimate user
	// has already used it. Every flow that validates a code against this
	// credential - including forgot-password, which otherwise deliberately
	// bypasses FailedAttempts/LockedUntil - must still advance this.
	LastUsedCounter *int64

	CreatedAt time.Time
	UpdatedAt time.Time
}

// New constructs a Credential for userID with a freshly-issued setup
// challenge: secretEncrypted is stored, and setupTokenHash identifies the
// token (never the token itself) a client must present to complete setup
// within setupTTL.
func New(userID uuid.UUID, secretEncrypted []byte, setupTokenHash string, setupTTL time.Duration) *Credential {
	now := time.Now().UTC()
	expiresAt := now.Add(setupTTL)
	return &Credential{
		UserID:              userID,
		SecretEncrypted:     secretEncrypted,
		SetupTokenHash:      &setupTokenHash,
		SetupTokenExpiresAt: &expiresAt,
		CreatedAt:           now,
		UpdatedAt:           now,
	}
}

// BeginSetup regenerates c's secret and setup challenge, invalidating
// whatever secret/token it held before. Used both for a brand new
// credential's initial setup and to let a user who never finished setup
// (or lost their authenticator) start over - always gated on the caller
// having already proven the account's current password (see
// application/auth.Service.Login).
func (c *Credential) BeginSetup(secretEncrypted []byte, setupTokenHash string, setupTTL time.Duration) {
	now := time.Now().UTC()
	expiresAt := now.Add(setupTTL)
	c.SecretEncrypted = secretEncrypted
	c.SetupTokenHash = &setupTokenHash
	c.SetupTokenExpiresAt = &expiresAt
	c.EnabledAt = nil
	c.FailedAttempts = 0
	c.LockedUntil = nil
	c.UpdatedAt = now
}

// Enable marks c as fully enrolled and clears the now-consumed setup
// challenge, so it can never be presented again.
func (c *Credential) Enable() {
	now := time.Now().UTC()
	c.EnabledAt = &now
	c.SetupTokenHash = nil
	c.SetupTokenExpiresAt = nil
	c.UpdatedAt = now
}

// IsEnabled reports whether setup has been completed - i.e. whether this
// credential may be used to gate a login.
func (c *Credential) IsEnabled() bool {
	return c.EnabledAt != nil
}

// IsSetupTokenExpired reports whether c's pending setup challenge (if any)
// has passed its validity window.
func (c *Credential) IsSetupTokenExpired() bool {
	return c.SetupTokenExpiresAt == nil || time.Now().UTC().After(*c.SetupTokenExpiresAt)
}

// IsLocked reports whether c is currently within an account-level OTP
// lockout window.
func (c *Credential) IsLocked() bool {
	return c.LockedUntil != nil && time.Now().UTC().Before(*c.LockedUntil)
}

// RecordFailure increments the failed-attempt counter and, once it reaches
// maxAttempts, starts a lockout of lockoutFor and resets the counter.
func (c *Credential) RecordFailure(maxAttempts int, lockoutFor time.Duration) {
	c.FailedAttempts++
	if c.FailedAttempts >= maxAttempts {
		lockedUntil := time.Now().UTC().Add(lockoutFor)
		c.LockedUntil = &lockedUntil
		c.FailedAttempts = 0
	}
	c.UpdatedAt = time.Now().UTC()
}

// RecordSuccess clears the failure counter and any active lockout, and
// advances the anti-replay counter to counter (see MarkCodeUsed).
func (c *Credential) RecordSuccess(counter int64) {
	c.FailedAttempts = 0
	c.LockedUntil = nil
	c.MarkCodeUsed(counter)
}

// IsCodeConsumed reports whether counter (an RFC 6238 time-step counter a
// candidate code validated against) has already been used to authenticate,
// or is older than one that has - either way it must be rejected.
func (c *Credential) IsCodeConsumed(counter int64) bool {
	return c.LastUsedCounter != nil && counter <= *c.LastUsedCounter
}

// MarkCodeUsed records counter as the most recently accepted TOTP step, so
// it - or any earlier step - can never authenticate again. This must be
// called for every successful validation, independent of RecordSuccess:
// forgot-password validates against this same credential but deliberately
// does not touch FailedAttempts/LockedUntil.
func (c *Credential) MarkCodeUsed(counter int64) {
	c.LastUsedCounter = &counter
	c.UpdatedAt = time.Now().UTC()
}
