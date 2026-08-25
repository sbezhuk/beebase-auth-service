// Package auth implements the authentication use cases: register, login,
// refresh-token rotation, logout, and current-user lookup. It depends only
// on the domain ports and the small ports declared in this package, never
// on HTTP or PostgreSQL directly.
package auth

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/sbezhuk/BeeBase-Server/internal/domain/token"
	"github.com/sbezhuk/BeeBase-Server/internal/domain/user"
	"github.com/sbezhuk/BeeBase-Server/internal/platform/tokenhash"
)

// Service implements the authentication use cases.
type Service struct {
	users         user.Repository
	refreshTokens token.Repository
	hasher        PasswordHasher
	issuer        AccessTokenIssuer
	refreshTTL    time.Duration
}

// NewService constructs a Service. refreshTTL is how long a freshly issued
// refresh token remains valid.
func NewService(
	users user.Repository,
	refreshTokens token.Repository,
	hasher PasswordHasher,
	issuer AccessTokenIssuer,
	refreshTTL time.Duration,
) *Service {
	return &Service{
		users:         users,
		refreshTokens: refreshTokens,
		hasher:        hasher,
		issuer:        issuer,
		refreshTTL:    refreshTTL,
	}
}

// Register creates a new user and returns an established session for them.
func (s *Service) Register(ctx context.Context, in RegisterInput) (*Session, error) {
	hash, err := s.hasher.Hash(in.Password)
	if err != nil {
		return nil, fmt.Errorf("auth: hash password: %w", err)
	}

	u := user.New(normalizeEmail(in.Email), hash)
	if err := s.users.Create(ctx, u); err != nil {
		return nil, err
	}

	return s.issueSession(ctx, u)
}

// Login verifies email/password and returns an established session.
func (s *Service) Login(ctx context.Context, in LoginInput) (*Session, error) {
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

	return s.issueSession(ctx, u)
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

func (s *Service) issueSession(ctx context.Context, u *user.User) (*Session, error) {
	accessToken, expiresAt, err := s.issuer.Issue(u.ID)
	if err != nil {
		return nil, fmt.Errorf("auth: issue access token: %w", err)
	}

	rawRefresh, err := tokenhash.Generate()
	if err != nil {
		return nil, fmt.Errorf("auth: generate refresh token: %w", err)
	}

	rt := token.New(u.ID, tokenhash.Hash(rawRefresh), s.refreshTTL)
	if err := s.refreshTokens.Create(ctx, rt); err != nil {
		return nil, fmt.Errorf("auth: store refresh token: %w", err)
	}

	return &Session{
		UserID:               u.ID,
		Email:                u.Email,
		AccessToken:          accessToken,
		AccessTokenExpiresAt: expiresAt,
		RefreshToken:         rawRefresh,
	}, nil
}

// normalizeEmail makes email comparison and storage case-insensitive: an
// account's identity is its lowercased, trimmed email address.
func normalizeEmail(email string) string {
	return strings.ToLower(strings.TrimSpace(email))
}
