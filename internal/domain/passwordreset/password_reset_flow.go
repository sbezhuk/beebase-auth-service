// Package passwordreset holds the PasswordResetFlow entity - the secure
// temporary state carrying the forgot-password flow through
// "email submitted -> OTP verified -> password reset" - and the port
// through which the application persists and retrieves it.
package passwordreset

import (
	"time"

	"github.com/google/uuid"
)

// PasswordResetFlow tracks one forgot-password attempt end to end. UserID
// is nil whenever the originating request was ineligible (unknown email,
// or the account has no enabled TOTP credential): the flow still exists
// and behaves identically to a real one from the caller's point of view,
// so its responses never leak whether the email was recognized.
//
// The flow has two independent gates, both required before Confirm can
// succeed: OTPVerifiedAt must be set (proves the OTP step), and
// ResetTokenHash must match (proves the caller is continuing the same
// flow, not skipping straight to confirm with a guessed/leaked flow
// token).
type PasswordResetFlow struct {
	ID     uuid.UUID
	UserID *uuid.UUID

	FlowTokenHash string

	OTPVerifiedAt *time.Time
	// OTPAttempts is a cap scoped to this flow alone, deliberately
	// independent of totp.Credential.FailedAttempts: guessing against a
	// reset flow requires no password, so it must never be able to lock
	// the real account out of logging in.
	OTPAttempts int

	ResetTokenHash      *string
	ResetTokenExpiresAt *time.Time

	ExpiresAt  time.Time
	ConsumedAt *time.Time
	CreatedAt  time.Time
}

// New constructs a PasswordResetFlow. userID is nil for an ineligible
// request. flowTokenHash is the hash of the opaque token returned to the
// caller (never the token itself).
func New(userID *uuid.UUID, flowTokenHash string, ttl time.Duration) *PasswordResetFlow {
	now := time.Now().UTC()
	return &PasswordResetFlow{
		ID:            uuid.New(),
		UserID:        userID,
		FlowTokenHash: flowTokenHash,
		ExpiresAt:     now.Add(ttl),
		CreatedAt:     now,
	}
}

// IsExpired reports whether the flow's overall validity window has passed.
func (f *PasswordResetFlow) IsExpired() bool {
	return time.Now().UTC().After(f.ExpiresAt)
}

// IsConsumed reports whether the flow has already completed a password
// reset.
func (f *PasswordResetFlow) IsConsumed() bool {
	return f.ConsumedAt != nil
}

// IsOTPVerified reports whether the OTP step has already succeeded for
// this flow.
func (f *PasswordResetFlow) IsOTPVerified() bool {
	return f.OTPVerifiedAt != nil
}

// IsOTPLocked reports whether this flow has already exhausted its own
// attempt cap. Callers must check this before validating a code, not just
// after a failure - otherwise a correct code submitted after the cap was
// already reached would still succeed.
func (f *PasswordResetFlow) IsOTPLocked(maxAttempts int) bool {
	return f.OTPAttempts >= maxAttempts
}

// RecordOTPFailure increments this flow's own attempt counter and reports
// whether it has now reached maxAttempts, at which point the flow is dead
// (the caller must request a brand new one) - this never touches any
// account-level lockout.
func (f *PasswordResetFlow) RecordOTPFailure(maxAttempts int) (locked bool) {
	f.OTPAttempts++
	return f.OTPAttempts >= maxAttempts
}

// MarkOTPVerified records that the OTP step has succeeded.
func (f *PasswordResetFlow) MarkOTPVerified() {
	now := time.Now().UTC()
	f.OTPVerifiedAt = &now
}

// IssueResetToken attaches a fresh single-use reset token (as its hash) to
// an OTP-verified flow, valid for ttl.
func (f *PasswordResetFlow) IssueResetToken(hash string, ttl time.Duration) {
	expiresAt := time.Now().UTC().Add(ttl)
	f.ResetTokenHash = &hash
	f.ResetTokenExpiresAt = &expiresAt
}

// IsResetTokenValid reports whether f currently holds a live (issued,
// unexpired) reset token.
func (f *PasswordResetFlow) IsResetTokenValid() bool {
	return f.ResetTokenHash != nil && f.ResetTokenExpiresAt != nil && time.Now().UTC().Before(*f.ResetTokenExpiresAt)
}

// Consume marks the flow as fully used: the reset token (and the flow as a
// whole) can never be presented again.
func (f *PasswordResetFlow) Consume() {
	now := time.Now().UTC()
	f.ConsumedAt = &now
}
