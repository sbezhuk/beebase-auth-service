// Package auth implements the authentication use cases: register, login,
// refresh-token rotation, logout, current-user lookup, TOTP 2FA setup and
// verification, change-password, and OTP-gated password recovery. It
// depends only on the domain ports and the small ports declared in this
// package, never on HTTP or PostgreSQL directly.
package auth

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/sbezhuk/beebase-auth-service/internal/domain/loginchallenge"
	"github.com/sbezhuk/beebase-auth-service/internal/domain/passwordreset"
	"github.com/sbezhuk/beebase-auth-service/internal/domain/token"
	totpdomain "github.com/sbezhuk/beebase-auth-service/internal/domain/totp"
	"github.com/sbezhuk/beebase-auth-service/internal/domain/user"
	"github.com/sbezhuk/beebase-auth-service/internal/platform/tokenhash"
	"github.com/sbezhuk/beebase-auth-service/internal/platform/totp"
	"github.com/sbezhuk/beebase-auth-service/internal/platform/totpsecret"
)

// SecurityConfig groups the numeric/duration knobs that tune 2FA and
// password-recovery behavior. Grouped into one struct - rather than
// passing ~8 individual same-typed values positionally into NewService -
// purely to avoid a transposition bug; it carries no behavior of its own.
type SecurityConfig struct {
	RefreshTTL              time.Duration
	SetupTokenTTL           time.Duration
	LoginChallengeTTL       time.Duration
	PasswordResetFlowTTL    time.Duration
	PasswordResetTokenTTL   time.Duration
	OTPMaxAttempts          int
	OTPLockoutDuration      time.Duration
	ResetFlowMaxOTPAttempts int
	// TOTPIssuer is the label shown in the user's authenticator app (e.g.
	// "BeeBase") alongside their account name.
	TOTPIssuer string
}

// Service implements the authentication use cases.
type Service struct {
	users              user.Repository
	refreshTokens      token.Repository
	credentials        totpdomain.Repository
	loginChallenges    loginchallenge.Repository
	passwordResetFlows passwordreset.Repository
	hasher             PasswordHasher
	issuer             AccessTokenIssuer
	media              MediaClient
	cipher             *totpsecret.Cipher
	security           SecurityConfig
}

// NewService constructs a Service.
func NewService(
	users user.Repository,
	refreshTokens token.Repository,
	credentials totpdomain.Repository,
	loginChallenges loginchallenge.Repository,
	passwordResetFlows passwordreset.Repository,
	hasher PasswordHasher,
	issuer AccessTokenIssuer,
	media MediaClient,
	cipher *totpsecret.Cipher,
	security SecurityConfig,
) *Service {
	return &Service{
		users:              users,
		refreshTokens:      refreshTokens,
		credentials:        credentials,
		loginChallenges:    loginChallenges,
		passwordResetFlows: passwordResetFlows,
		hasher:             hasher,
		issuer:             issuer,
		media:              media,
		cipher:             cipher,
		security:           security,
	}
}

// Register creates a new user and issues a TOTP setup challenge for them.
// Registration is not complete - and no session is issued - until
// SetupVerifyOTP succeeds. An email that's already registered always
// conflicts, even if that account never finished 2FA setup: a caller who
// doesn't know the account's current password must never be able to use
// /register to overwrite it. Resuming an abandoned setup instead happens
// through Login, which already requires proving the current password.
func (s *Service) Register(ctx context.Context, in RegisterInput) (*RegisterResult, error) {
	hash, err := s.hasher.Hash(in.Password)
	if err != nil {
		return nil, fmt.Errorf("auth: hash password: %w", err)
	}

	u := user.New(normalizeEmail(in.Email), hash)
	if err := s.users.Create(ctx, u); err != nil {
		return nil, err
	}

	return s.beginTOTPSetup(ctx, u)
}

// Login verifies email/password and, on success, never issues a session
// directly: it always returns either an OTP challenge (2FA already
// enabled) or a fresh TOTP setup challenge (2FA never completed), per
// BEEB-33's requirement that credentials alone are never sufficient. An
// account whose setup was abandoned - or never started, e.g. a
// pre-2FA-rollout account - is transparently given a new setup challenge
// here rather than erroring, because reaching this point already proves
// the caller knows the current password.
func (s *Service) Login(ctx context.Context, in LoginInput) (*LoginResult, error) {
	u, err := s.users.GetByEmail(ctx, normalizeEmail(in.Email))
	if err != nil {
		if errors.Is(err, user.ErrNotFound) {
			return nil, ErrInvalidCredentials
		}
		return nil, err
	}

	if err := s.hasher.Verify(u.PasswordHash, in.Password); err != nil {
		return nil, ErrInvalidCredentials
	}

	cred, err := s.credentials.GetByUserID(ctx, u.ID)
	if err != nil && !errors.Is(err, totpdomain.ErrNotFound) {
		return nil, err
	}

	if err == nil && cred.IsEnabled() {
		return s.issueLoginChallenge(ctx, u)
	}

	setup, err := s.beginTOTPSetup(ctx, u)
	if err != nil {
		return nil, err
	}

	return &LoginResult{
		Status:     LoginStatusTOTPSetupRequired,
		SetupToken: setup.SetupToken,
		OtpauthURI: setup.OtpauthURI,
		Secret:     setup.Secret,
		ExpiresAt:  setup.ExpiresAt,
	}, nil
}

// Refresh rotates rawToken: the presented token is revoked and a new
// access/refresh pair is issued. Presenting a token that was already
// revoked is treated as evidence of theft, so it revokes every refresh
// token belonging to that user rather than just failing quietly.
func (s *Service) Refresh(ctx context.Context, rawToken string) (*Session, error) {
	rt, err := s.refreshTokens.GetByHash(ctx, tokenhash.Hash(rawToken))
	if err != nil {
		if errors.Is(err, token.ErrNotFound) {
			return nil, ErrInvalidRefreshToken
		}
		return nil, err
	}

	if rt.IsRevoked() {
		if err := s.refreshTokens.RevokeAllForUser(ctx, rt.UserID); err != nil {
			return nil, fmt.Errorf("auth: revoke all after reuse: %w", err)
		}
		return nil, ErrInvalidRefreshToken
	}

	if rt.IsExpired() {
		return nil, ErrInvalidRefreshToken
	}

	if err := s.refreshTokens.Revoke(ctx, rt.ID); err != nil {
		return nil, fmt.Errorf("auth: revoke rotated token: %w", err)
	}

	u, err := s.users.GetByID(ctx, rt.UserID)
	if err != nil {
		return nil, err
	}

	return s.issueSession(ctx, u)
}

// Logout revokes rawToken. It is idempotent: presenting an unknown or
// already-revoked token is not an error, since the desired end state
// (the token can no longer be used) already holds.
func (s *Service) Logout(ctx context.Context, rawToken string) error {
	rt, err := s.refreshTokens.GetByHash(ctx, tokenhash.Hash(rawToken))
	if err != nil {
		if errors.Is(err, token.ErrNotFound) {
			return nil
		}
		return err
	}

	if rt.IsRevoked() {
		return nil
	}

	return s.refreshTokens.Revoke(ctx, rt.ID)
}

// CurrentUser returns the user identified by userID, as extracted from a
// verified access token.
func (s *Service) CurrentUser(ctx context.Context, userID uuid.UUID) (*user.User, error) {
	return s.users.GetByID(ctx, userID)
}

// UpdateProfile applies in to the profile identified by userID (extracted
// from a verified access token, so a caller can only ever update their
// own profile) and returns the updated user. accessToken is the caller's
// own access token, forwarded to media-service to verify ownership of a
// newly-referenced avatar id before it's persisted - see
// AvatarChange.
func (s *Service) UpdateProfile(ctx context.Context, userID uuid.UUID, accessToken string, in UpdateProfileInput) (*user.User, error) {
	u, err := s.users.GetByID(ctx, userID)
	if err != nil {
		return nil, err
	}

	avatarMediaID := u.AvatarMediaID
	if in.Avatar != nil {
		if in.Avatar.MediaID != nil {
			if err := s.media.VerifyOwnership(ctx, accessToken, []uuid.UUID{*in.Avatar.MediaID}); err != nil {
				return nil, err
			}
			avatarMediaID = in.Avatar.MediaID
		} else {
			avatarMediaID = nil
		}
	}

	u.UpdateProfile(in.FirstName, in.LastName, avatarMediaID)

	if err := s.users.Update(ctx, u); err != nil {
		return nil, err
	}

	return u, nil
}

func (s *Service) issueSession(ctx context.Context, u *user.User) (*Session, error) {
	accessToken, expiresAt, err := s.issuer.Issue(u.ID)
	if err != nil {
		return nil, fmt.Errorf("auth: issue access token: %w", err)
	}

	rawRefresh, err := tokenhash.Generate()
	if err != nil {
		return nil, fmt.Errorf("auth: generate refresh token: %w", err)
	}

	rt := token.New(u.ID, tokenhash.Hash(rawRefresh), s.security.RefreshTTL)
	if err := s.refreshTokens.Create(ctx, rt); err != nil {
		return nil, fmt.Errorf("auth: store refresh token: %w", err)
	}

	return &Session{
		UserID:                u.ID,
		Email:                 u.Email,
		AccessToken:           accessToken,
		AccessTokenExpiresAt:  expiresAt,
		RefreshToken:          rawRefresh,
		RefreshTokenExpiresAt: rt.ExpiresAt,
	}, nil
}

// issueLoginChallenge creates the OTP-required gate for a 2FA-enabled
// account whose password just checked out.
func (s *Service) issueLoginChallenge(ctx context.Context, u *user.User) (*LoginResult, error) {
	rawToken, err := tokenhash.Generate()
	if err != nil {
		return nil, fmt.Errorf("auth: generate login challenge token: %w", err)
	}

	c := loginchallenge.New(u.ID, tokenhash.Hash(rawToken), s.security.LoginChallengeTTL)
	if err := s.loginChallenges.Create(ctx, c); err != nil {
		return nil, fmt.Errorf("auth: store login challenge: %w", err)
	}

	return &LoginResult{
		Status:         LoginStatusOTPRequired,
		ChallengeToken: rawToken,
		ExpiresAt:      c.ExpiresAt,
	}, nil
}

// beginTOTPSetup generates a fresh secret and setup challenge for u,
// creating its credential row on the first attempt or replacing the
// pending one otherwise - Credential.BeginSetup invalidates whatever
// secret/token existed before, so an abandoned setup or a lost
// authenticator can always be safely restarted by whoever can prove they
// hold the account's current password.
func (s *Service) beginTOTPSetup(ctx context.Context, u *user.User) (*RegisterResult, error) {
	secretBase32, otpauthURI, err := totp.GenerateSecret(s.security.TOTPIssuer, u.Email)
	if err != nil {
		return nil, fmt.Errorf("auth: generate totp secret: %w", err)
	}

	encryptedSecret, err := s.cipher.Encrypt([]byte(secretBase32))
	if err != nil {
		return nil, fmt.Errorf("auth: encrypt totp secret: %w", err)
	}

	rawSetupToken, err := tokenhash.Generate()
	if err != nil {
		return nil, fmt.Errorf("auth: generate setup token: %w", err)
	}
	setupTokenHash := tokenhash.Hash(rawSetupToken)

	cred, err := s.credentials.GetByUserID(ctx, u.ID)
	if err != nil {
		if !errors.Is(err, totpdomain.ErrNotFound) {
			return nil, err
		}
		cred = totpdomain.New(u.ID, encryptedSecret, setupTokenHash, s.security.SetupTokenTTL)
		if err := s.credentials.Create(ctx, cred); err != nil {
			return nil, fmt.Errorf("auth: create totp credential: %w", err)
		}
	} else {
		cred.BeginSetup(encryptedSecret, setupTokenHash, s.security.SetupTokenTTL)
		if err := s.credentials.Update(ctx, cred); err != nil {
			return nil, fmt.Errorf("auth: update totp credential: %w", err)
		}
	}

	return &RegisterResult{
		UserID:     u.ID,
		SetupToken: rawSetupToken,
		OtpauthURI: otpauthURI,
		Secret:     secretBase32,
		ExpiresAt:  *cred.SetupTokenExpiresAt,
	}, nil
}

// normalizeEmail makes email comparison and storage case-insensitive: an
// account's identity is its lowercased, trimmed email address.
func normalizeEmail(email string) string {
	return strings.ToLower(strings.TrimSpace(email))
}
