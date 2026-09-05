package auth

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"

	"github.com/sbezhuk/beebase-auth-service/internal/domain/loginchallenge"
	totpdomain "github.com/sbezhuk/beebase-auth-service/internal/domain/totp"
	"github.com/sbezhuk/beebase-auth-service/internal/platform/tokenhash"
	"github.com/sbezhuk/beebase-auth-service/internal/platform/totp"
)

// verifyOTP checks code against cred's decrypted secret, applying and
// persisting cred's account-level lockout state either way. This is the
// one shared gate for every flow that has already proven password
// knowledge - setup-verify, login-verify-otp, change-password. Forgot-
// password deliberately does not go through this: see
// service_password_reset.go for why its lockout must stay independent (it
// still enforces the anti-replay check below against the same credential).
func (s *Service) verifyOTP(ctx context.Context, cred *totpdomain.Credential, code string) error {
	if cred.IsLocked() {
		return ErrOTPLocked
	}

	secret, err := s.cipher.Decrypt(cred.SecretEncrypted)
	if err != nil {
		return fmt.Errorf("auth: decrypt totp secret: %w", err)
	}

	ok, counter := totp.ValidateAt(code, string(secret), time.Now().UTC())
	if ok && cred.IsCodeConsumed(counter) {
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

// SetupVerifyOTP completes a pending TOTP setup: setupToken identifies the
// challenge (issued by Register or a Login-triggered setup), code must be
// a currently-valid TOTP for the secret issued with it. On success the
// credential becomes enabled and a full session is issued - this is the
// only path that can ever turn a pending setup into "registration
// complete."
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

	if err := s.verifyOTP(ctx, cred, code); err != nil {
		return nil, err
	}

	cred.Enable()
	if err := s.credentials.Update(ctx, cred); err != nil {
		return nil, fmt.Errorf("auth: enable totp credential: %w", err)
	}

	u, err := s.users.GetByID(ctx, cred.UserID)
	if err != nil {
		return nil, err
	}

	return s.issueSession(ctx, u)
}

// LoginVerifyOTP completes a login begun by Login: challengeToken
// identifies the pending challenge, code must be a currently-valid TOTP
// for the account's enabled credential. On success the challenge is
// consumed (single-use) and a full session is issued.
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

	if err := s.verifyOTP(ctx, cred, code); err != nil {
		return nil, err
	}

	if err := s.loginChallenges.Consume(ctx, challenge.ID); err != nil {
		return nil, fmt.Errorf("auth: consume login challenge: %w", err)
	}

	u, err := s.users.GetByID(ctx, challenge.UserID)
	if err != nil {
		return nil, err
	}

	return s.issueSession(ctx, u)
}

// ChangePassword replaces userID's password. in.CurrentPassword must match
// the account's existing password and in.OTP must be a currently-valid
// TOTP for its enabled credential - knowing the current password alone is
// never sufficient. Nothing is persisted unless both checks succeed. On
// success, every refresh token belonging to the account is revoked as a
// defense-in-depth measure, since a password change is itself a
// credential-security event.
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

	if err := s.verifyOTP(ctx, cred, in.OTP); err != nil {
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

	return nil
}
