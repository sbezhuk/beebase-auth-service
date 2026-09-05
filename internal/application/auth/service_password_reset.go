package auth

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"

	"github.com/sbezhuk/beebase-auth-service/internal/domain/passwordreset"
	totpdomain "github.com/sbezhuk/beebase-auth-service/internal/domain/totp"
	"github.com/sbezhuk/beebase-auth-service/internal/domain/user"
	"github.com/sbezhuk/beebase-auth-service/internal/platform/tokenhash"
	"github.com/sbezhuk/beebase-auth-service/internal/platform/totp"
)

// RequestPasswordReset always succeeds and always returns a result with
// the same shape, regardless of whether email belongs to a real,
// 2FA-enabled account: the created flow's UserID is populated only when it
// does, so nothing about this response - or VerifyPasswordResetOTP's
// later behavior against it - can tell a caller which case they're in.
func (s *Service) RequestPasswordReset(ctx context.Context, email string) (*PasswordResetRequestResult, error) {
	var eligibleUserID *uuid.UUID

	u, err := s.users.GetByEmail(ctx, normalizeEmail(email))
	switch {
	case err == nil:
		cred, credErr := s.credentials.GetByUserID(ctx, u.ID)
		if credErr != nil && !errors.Is(credErr, totpdomain.ErrNotFound) {
			return nil, credErr
		}
		if credErr == nil && cred.IsEnabled() {
			id := u.ID
			eligibleUserID = &id
		}
	case errors.Is(err, user.ErrNotFound):
		// Leave eligibleUserID nil: an unknown email behaves identically
		// to a known-but-ineligible one.
	default:
		return nil, err
	}

	rawFlowToken, err := tokenhash.Generate()
	if err != nil {
		return nil, fmt.Errorf("auth: generate password reset flow token: %w", err)
	}

	flow := passwordreset.New(eligibleUserID, tokenhash.Hash(rawFlowToken), s.security.PasswordResetFlowTTL)
	if err := s.passwordResetFlows.Create(ctx, flow); err != nil {
		return nil, fmt.Errorf("auth: store password reset flow: %w", err)
	}

	return &PasswordResetRequestResult{FlowToken: rawFlowToken, ExpiresAt: flow.ExpiresAt}, nil
}

// VerifyPasswordResetOTP checks code against the flow identified by
// flowToken. If the flow is ineligible (its UserID is nil - unknown email
// or no enabled 2FA at request time), this always fails through the exact
// same flow-scoped attempt-cap bookkeeping a real account's flow would go
// through, so neither the response shape nor the attempt-cap behavior
// reveals which case occurred. Failures here never touch any
// account-level lockout (totp.Credential.FailedAttempts): a flow requires
// no password to reach, so guessing against it must never be able to lock
// the real account out of logging in.
func (s *Service) VerifyPasswordResetOTP(ctx context.Context, flowToken, code string) (*PasswordResetOTPResult, error) {
	flow, err := s.passwordResetFlows.GetByFlowTokenHash(ctx, tokenhash.Hash(flowToken))
	if err != nil {
		if errors.Is(err, passwordreset.ErrNotFound) {
			return nil, ErrPasswordResetFlowInvalid
		}
		return nil, err
	}

	if flow.IsExpired() || flow.IsConsumed() || flow.IsOTPVerified() {
		return nil, ErrPasswordResetFlowInvalid
	}

	if flow.IsOTPLocked(s.security.ResetFlowMaxOTPAttempts) {
		return nil, ErrOTPLocked
	}

	valid := false
	if flow.UserID != nil {
		cred, credErr := s.credentials.GetByUserID(ctx, *flow.UserID)
		if credErr != nil && !errors.Is(credErr, totpdomain.ErrNotFound) {
			return nil, credErr
		}
		if credErr == nil && cred.IsEnabled() {
			secret, err := s.cipher.Decrypt(cred.SecretEncrypted)
			if err != nil {
				return nil, fmt.Errorf("auth: decrypt totp secret: %w", err)
			}
			// Anti-replay (see service_totp.go/BEEB-41) applies here too:
			// a code intercepted during a real login must not also be
			// usable to hijack a password reset. This is the one thing
			// this flow does write back to cred - it must never touch
			// FailedAttempts/LockedUntil (see the flow's own otp_attempts
			// cap above), but a used code is used account-wide, not just
			// within this flow.
			if ok, counter := totp.ValidateAt(code, string(secret), time.Now().UTC()); ok && !cred.IsCodeConsumed(counter) {
				valid = true
				cred.MarkCodeUsed(counter)
				if err := s.credentials.Update(ctx, cred); err != nil {
					return nil, fmt.Errorf("auth: persist totp anti-replay state: %w", err)
				}
			}
		}
	}

	if !valid {
		locked := flow.RecordOTPFailure(s.security.ResetFlowMaxOTPAttempts)
		if err := s.passwordResetFlows.Update(ctx, flow); err != nil {
			return nil, fmt.Errorf("auth: persist password reset otp failure: %w", err)
		}
		if locked {
			return nil, ErrOTPLocked
		}
		return nil, ErrOTPInvalid
	}

	rawResetToken, err := tokenhash.Generate()
	if err != nil {
		return nil, fmt.Errorf("auth: generate password reset token: %w", err)
	}

	flow.MarkOTPVerified()
	flow.IssueResetToken(tokenhash.Hash(rawResetToken), s.security.PasswordResetTokenTTL)
	if err := s.passwordResetFlows.Update(ctx, flow); err != nil {
		return nil, fmt.Errorf("auth: persist password reset otp success: %w", err)
	}

	return &PasswordResetOTPResult{ResetToken: rawResetToken, ExpiresAt: *flow.ResetTokenExpiresAt}, nil
}

// ConfirmPasswordReset sets a new password for the account behind
// resetToken. This can never succeed without a prior successful
// VerifyPasswordResetOTP against the same flow: a live reset token, a set
// OTPVerifiedAt, and a non-nil UserID (which can only be non-nil if
// RequestPasswordReset found a real, 2FA-enabled account) are all
// required - so skipping straight to this endpoint is structurally
// impossible, not just a policy choice. Every refresh token belonging to
// the account is revoked, per BEEB-34's requirement that a password
// recovery invalidates existing sessions.
func (s *Service) ConfirmPasswordReset(ctx context.Context, resetToken, newPassword string) error {
	flow, err := s.passwordResetFlows.GetByResetTokenHash(ctx, tokenhash.Hash(resetToken))
	if err != nil {
		if errors.Is(err, passwordreset.ErrNotFound) {
			return ErrPasswordResetTokenInvalid
		}
		return err
	}

	if flow.IsExpired() || flow.IsConsumed() || !flow.IsOTPVerified() || !flow.IsResetTokenValid() || flow.UserID == nil {
		return ErrPasswordResetTokenInvalid
	}

	newHash, err := s.hasher.Hash(newPassword)
	if err != nil {
		return fmt.Errorf("auth: hash new password: %w", err)
	}

	if err := s.users.UpdatePassword(ctx, *flow.UserID, newHash); err != nil {
		return err
	}

	flow.Consume()
	if err := s.passwordResetFlows.Update(ctx, flow); err != nil {
		return fmt.Errorf("auth: consume password reset flow: %w", err)
	}

	if err := s.refreshTokens.RevokeAllForUser(ctx, *flow.UserID); err != nil {
		return fmt.Errorf("auth: revoke sessions after password reset: %w", err)
	}

	return nil
}
