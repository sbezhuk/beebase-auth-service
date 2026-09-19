package auth

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"

	"github.com/sbezhuk/beebase-auth-service/internal/domain/loginchallenge"
	totpdomain "github.com/sbezhuk/beebase-auth-service/internal/domain/totp"
	"github.com/sbezhuk/beebase-auth-service/internal/domain/user"
	"github.com/sbezhuk/beebase-auth-service/internal/platform/tokenhash"
	"github.com/sbezhuk/beebase-auth-service/internal/platform/totp"
)

const (
	demoAccountEmail = "demo@gmail.com"
	demoOTPCode      = "123456"
)

// verifyOTP checks code against cred's decrypted secret, applying and
// persisting cred's account-level lockout state either way. This is the
// one shared gate for every flow that has already proven password
// knowledge - setup-verify, login-verify-otp, change-password. Forgot-
// password deliberately does not go through this: see
// service_password_reset.go for why its lockout must stay independent (it
// still enforces the anti-replay check below against the same credential).
func (s *Service) verifyOTP(ctx context.Context, email string, cred *totpdomain.Credential, code string) error {
	if cred.IsLocked() {
		return ErrOTPLocked
	}

	ok, counter, demoCode, err := s.validateOTP(email, cred, code)
	if err != nil {
		return err
	}
	if ok && !demoCode && cred.IsCodeConsumed(counter) {
		// Mathematically valid, but already used (or superseded by a later
		// code) - see BEEB-41: without this, a captured code stays usable
		// for the rest of the skew window even after the legitimate user
		// already used it.
		ok = false
	}

	if !ok {
		cred.RecordFailure(s.security.OTPMaxAttempts, s.security.OTPLockoutDuration)
		if err := s.credentials.Update(ctx, cred); err != nil {
			return fmt.Errorf("auth: persist otp failure: %w", err)
		}
		if cred.IsLocked() {
			return ErrOTPLocked
		}
		return ErrOTPInvalid
	}

	cred.RecordSuccess(counter)
	if err := s.credentials.Update(ctx, cred); err != nil {
		return fmt.Errorf("auth: persist otp success: %w", err)
	}

	return nil
}

// validateOTP is the single account-aware TOTP validation point. The demo
// code is deliberately scoped to one exact account and does not replace
// secret generation or ordinary TOTP validation.
func (s *Service) validateOTP(email string, cred *totpdomain.Credential, code string) (ok bool, counter int64, demoCode bool, err error) {
	if email == demoAccountEmail && code == demoOTPCode {
		// A fixed code has no real TOTP counter. Keep the sentinel below out of
		// anti-replay comparisons while still recording a successful attempt.
		return true, 0, true, nil
	}

	secret, err := s.cipher.Decrypt(cred.SecretEncrypted)
	if err != nil {
		return false, 0, false, fmt.Errorf("auth: decrypt totp secret: %w", err)
	}

	ok, counter = totp.ValidateAt(code, string(secret), time.Now().UTC())
	return ok, counter, false, nil
}

// SetupVerifyOTP completes a pending TOTP setup: setupToken identifies the
// challenge (issued by Register or a Login-triggered setup), code must be
// a currently-valid TOTP for the secret issued with it. On success the
// credential becomes enabled and a full session is issued - this is the
// only path that can ever turn a pending setup into "registration
// complete."
//
// The credential is only marked enabled (and its now-used setup token
// cleared) once issueSession has actually succeeded - never before. If
// finalization happened first and issueSession then failed for any reason,
// a legitimate retry with the very same (still otherwise-valid) setup
// token would find it already consumed and be turned away with a
// confusing "invalid or expired setup token", even though the OTP the
// caller proved knowledge of was genuinely valid. The OTP itself is
// already replay-proof independent of this ordering - verifyOTP durably
// records its anti-replay counter (see Credential.RecordSuccess) before
// this function does anything else - so deferring Enable()/Update this
// way costs nothing in security, only in how early "setup complete" is
// persisted.
func (s *Service) SetupVerifyOTP(ctx context.Context, setupToken, code string) (*Session, error) {
	cred, err := s.credentials.GetBySetupTokenHash(ctx, tokenhash.Hash(setupToken))
	if err != nil {
		if errors.Is(err, totpdomain.ErrNotFound) {
			return nil, ErrSetupTokenInvalid
		}
		return nil, err
	}

	if cred.IsSetupTokenExpired() {
		return nil, ErrSetupTokenInvalid
	}

	u, err := s.users.GetByID(ctx, cred.UserID)
	if err != nil {
		return nil, err
	}

	if err := s.verifyOTP(ctx, u.Email, cred, code); err != nil {
		return nil, err
	}

	if u.DeletionStatus == user.DeletionStatusPending {
		return nil, ErrInvalidCredentials
	}

	session, err := s.issueSession(ctx, u)
	if err != nil {
		return nil, err
	}

	cred.Enable()
	if err := s.credentials.Update(ctx, cred); err != nil {
		return nil, fmt.Errorf("auth: enable totp credential: %w", err)
	}

	return session, nil
}

// LoginVerifyOTP completes a login begun by Login: challengeToken
// identifies the pending challenge, code must be a currently-valid TOTP
// for the account's enabled credential. On success the challenge is
// consumed (single-use) and a full session is issued.
//
// The challenge is only consumed once issueSession has actually succeeded
// - never before. Consuming it first and issuing the session second would
// mean any failure in issueSession (including one entirely unrelated to
// the challenge or the OTP, e.g. a downstream dependency blip) permanently
// burns a challenge that was never actually used to complete a login; a
// legitimate retry with the same challenge and a fresh valid OTP would
// then be turned away with a misleading "invalid or expired login
// challenge" - indistinguishable, from the caller's side, from their
// session having genuinely expired. The OTP itself is already
// replay-proof independent of this ordering - verifyOTP durably records
// its anti-replay counter (see Credential.RecordSuccess) before this
// function does anything else - so deferring Consume this way costs
// nothing in security: a captured request still can't be replayed with
// the same OTP, and once Consume does run (immediately after a real
// success), the challenge is single-use exactly as before.
func (s *Service) LoginVerifyOTP(ctx context.Context, challengeToken, code string) (*Session, error) {
	challenge, err := s.loginChallenges.GetByHash(ctx, tokenhash.Hash(challengeToken))
	if err != nil {
		if errors.Is(err, loginchallenge.ErrNotFound) {
			return nil, ErrChallengeInvalid
		}
		return nil, err
	}

	if challenge.IsExpired() || challenge.IsConsumed() {
		return nil, ErrChallengeInvalid
	}

	cred, err := s.credentials.GetByUserID(ctx, challenge.UserID)
	if err != nil {
		if errors.Is(err, totpdomain.ErrNotFound) {
			return nil, ErrChallengeInvalid
		}
		return nil, err
	}

	u, err := s.users.GetByID(ctx, challenge.UserID)
	if err != nil {
		return nil, err
	}

	if err := s.verifyOTP(ctx, u.Email, cred, code); err != nil {
		return nil, err
	}

	if u.DeletionStatus == user.DeletionStatusPending {
		return nil, ErrChallengeInvalid
	}

	session, err := s.issueSession(ctx, u)
	if err != nil {
		return nil, err
	}

	if err := s.loginChallenges.Consume(ctx, challenge.ID); err != nil {
		return nil, fmt.Errorf("auth: consume login challenge: %w", err)
	}

	return session, nil
}

// ChangePassword replaces userID's password. in.CurrentPassword must match
// the account's existing password and in.OTP must be a currently-valid
// TOTP for its enabled credential - knowing the current password alone is
// never sufficient. Nothing is persisted unless both checks succeed. On
// success, every refresh token belonging to the account is revoked and its
// session immediately deactivated - so its access token stops being
// accepted right away too - as a defense-in-depth measure, since a
// password change is itself a credential-security event.
//
// Session invalidation (RevokeAllForUser, DeactivateAndReturnPrevious)
// remains synchronous and must succeed for ChangePassword itself to
// succeed - it is security-critical, not best-effort. Once it has
// succeeded, whatever session was just invalidated has its
// push-notification device data cleaned up separately, in the background,
// via the same best-effort cleanupSessionDevices mechanism Logout and
// session replacement already use: notification-service being slow,
// unreachable, or erroring must never turn an already-completed password
// change into an error, and it never gates or delays this method
// returning.
func (s *Service) ChangePassword(ctx context.Context, userID uuid.UUID, in ChangePasswordInput) error {
	u, err := s.users.GetByID(ctx, userID)
	if err != nil {
		return err
	}

	if err := s.hasher.Verify(u.PasswordHash, in.CurrentPassword); err != nil {
		return ErrCurrentPasswordInvalid
	}

	cred, err := s.credentials.GetByUserID(ctx, userID)
	if err != nil {
		if errors.Is(err, totpdomain.ErrNotFound) {
			// Reaching an authenticated endpoint without an enabled
			// credential shouldn't be possible - a session can only be
			// issued via SetupVerifyOTP, LoginVerifyOTP, or a Refresh
			// descending from one of those - but fail closed rather than
			// panic if it somehow happens.
			return ErrOTPInvalid
		}
		return err
	}

	if err := s.verifyOTP(ctx, u.Email, cred, in.OTP); err != nil {
		return err
	}

	newHash, err := s.hasher.Hash(in.NewPassword)
	if err != nil {
		return fmt.Errorf("auth: hash new password: %w", err)
	}

	if err := s.users.UpdatePassword(ctx, userID, newHash); err != nil {
		return err
	}

	if err := s.refreshTokens.RevokeAllForUser(ctx, userID); err != nil {
		return fmt.Errorf("auth: revoke sessions after password change: %w", err)
	}

	previousSessionID, hadPrevious, err := s.sessions.DeactivateAndReturnPrevious(ctx, userID)
	if err != nil {
		return fmt.Errorf("auth: deactivate session after password change: %w", err)
	}
	if hadPrevious {
		s.cleanupSessionDevices(userID, previousSessionID)
	}

	return nil
}
