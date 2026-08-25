package auth_test

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"

	appauth "github.com/sbezhuk/BeeBase-Server/internal/application/auth"
	"github.com/sbezhuk/BeeBase-Server/internal/domain/token"
	"github.com/sbezhuk/BeeBase-Server/internal/domain/user"
	"github.com/sbezhuk/BeeBase-Server/internal/platform/jwtauth"
	"github.com/sbezhuk/BeeBase-Server/internal/platform/password"
)

// --- in-memory fakes for the domain ports ---

type fakeUserRepo struct {
	mu      sync.Mutex
	byID    map[uuid.UUID]*user.User
	byEmail map[string]*user.User
}

func newFakeUserRepo() *fakeUserRepo {
	return &fakeUserRepo{byID: map[uuid.UUID]*user.User{}, byEmail: map[string]*user.User{}}
}

func (f *fakeUserRepo) Create(_ context.Context, u *user.User) error {
	f.mu.Lock()
	defer f.mu.Unlock()

	if _, exists := f.byEmail[u.Email]; exists {
		return user.ErrEmailTaken
	}

	cp := *u
	f.byID[u.ID] = &cp
	f.byEmail[u.Email] = &cp
	return nil
}

func (f *fakeUserRepo) GetByEmail(_ context.Context, email string) (*user.User, error) {
	f.mu.Lock()
	defer f.mu.Unlock()

	u, ok := f.byEmail[email]
	if !ok {
		return nil, user.ErrNotFound
	}
	cp := *u
	return &cp, nil
}

func (f *fakeUserRepo) GetByID(_ context.Context, id uuid.UUID) (*user.User, error) {
	f.mu.Lock()
	defer f.mu.Unlock()

	u, ok := f.byID[id]
	if !ok {
		return nil, user.ErrNotFound
	}
	cp := *u
	return &cp, nil
}

type fakeTokenRepo struct {
	mu     sync.Mutex
	byID   map[uuid.UUID]*token.RefreshToken
	byHash map[string]uuid.UUID
}

func newFakeTokenRepo() *fakeTokenRepo {
	return &fakeTokenRepo{byID: map[uuid.UUID]*token.RefreshToken{}, byHash: map[string]uuid.UUID{}}
}

func (f *fakeTokenRepo) Create(_ context.Context, t *token.RefreshToken) error {
	f.mu.Lock()
	defer f.mu.Unlock()

	cp := *t
	f.byID[t.ID] = &cp
	f.byHash[t.TokenHash] = t.ID
	return nil
}

func (f *fakeTokenRepo) GetByHash(_ context.Context, hash string) (*token.RefreshToken, error) {
	f.mu.Lock()
	defer f.mu.Unlock()

	id, ok := f.byHash[hash]
	if !ok {
		return nil, token.ErrNotFound
	}
	cp := *f.byID[id]
	return &cp, nil
}

func (f *fakeTokenRepo) Revoke(_ context.Context, id uuid.UUID) error {
	f.mu.Lock()
	defer f.mu.Unlock()

	t, ok := f.byID[id]
	if !ok {
		return nil
	}
	now := time.Now().UTC()
	t.RevokedAt = &now
	return nil
}

func (f *fakeTokenRepo) RevokeAllForUser(_ context.Context, userID uuid.UUID) error {
	f.mu.Lock()
	defer f.mu.Unlock()

	now := time.Now().UTC()
	for _, t := range f.byID {
		if t.UserID == userID && t.RevokedAt == nil {
			t.RevokedAt = &now
		}
	}
	return nil
}

// --- test harness ---

func newTestService() (*appauth.Service, *fakeUserRepo, *fakeTokenRepo) {
	users := newFakeUserRepo()
	tokens := newFakeTokenRepo()
	hasher := password.NewBcryptHasher(bcrypt.MinCost)
	issuer := jwtauth.NewIssuer("test-secret", time.Minute)

	svc := appauth.NewService(users, tokens, hasher, issuer, time.Hour)
	return svc, users, tokens
}

func mustRegister(t *testing.T, svc *appauth.Service, email, pw string) *appauth.Session {
	t.Helper()
	session, err := svc.Register(context.Background(), appauth.RegisterInput{Email: email, Password: pw})
	if err != nil {
		t.Fatalf("Register: %v", err)
	}
	return session
}

// --- Register ---

func TestRegister_Success(t *testing.T) {
	svc, _, _ := newTestService()

	session := mustRegister(t, svc, "Bee@Example.com", "supersecret")

	if session.Email != "bee@example.com" {
		t.Errorf("Email = %q, want normalized lowercase", session.Email)
	}
	if session.AccessToken == "" || session.RefreshToken == "" {
		t.Error("Register did not issue both tokens")
	}
}

func TestRegister_DuplicateEmail(t *testing.T) {
	svc, _, _ := newTestService()
	mustRegister(t, svc, "bee@example.com", "supersecret")

	_, err := svc.Register(context.Background(), appauth.RegisterInput{
		Email:    "bee@example.com",
		Password: "anotherpassword",
	})
	if !errors.Is(err, user.ErrEmailTaken) {
		t.Fatalf("Register with duplicate email: got %v, want ErrEmailTaken", err)
	}
}

func TestRegister_DuplicateEmailIsCaseInsensitive(t *testing.T) {
	svc, _, _ := newTestService()
	mustRegister(t, svc, "bee@example.com", "supersecret")

	_, err := svc.Register(context.Background(), appauth.RegisterInput{
		Email:    "BEE@EXAMPLE.COM",
		Password: "anotherpassword",
	})
	if !errors.Is(err, user.ErrEmailTaken) {
		t.Fatalf("Register with same email different case: got %v, want ErrEmailTaken", err)
	}
}

// --- Login ---

func TestLogin_Success(t *testing.T) {
	svc, _, _ := newTestService()
	mustRegister(t, svc, "bee@example.com", "supersecret")

	session, err := svc.Login(context.Background(), appauth.LoginInput{
		Email:    "bee@example.com",
		Password: "supersecret",
	})
	if err != nil {
		t.Fatalf("Login: %v", err)
	}
	if session.AccessToken == "" {
		t.Error("Login did not issue an access token")
	}
}

func TestLogin_WrongPassword(t *testing.T) {
	svc, _, _ := newTestService()
	mustRegister(t, svc, "bee@example.com", "supersecret")

	_, err := svc.Login(context.Background(), appauth.LoginInput{
		Email:    "bee@example.com",
		Password: "wrong-password",
	})
	if !errors.Is(err, appauth.ErrInvalidCredentials) {
		t.Fatalf("Login with wrong password: got %v, want ErrInvalidCredentials", err)
	}
}

func TestLogin_UnknownEmail(t *testing.T) {
	svc, _, _ := newTestService()

	_, err := svc.Login(context.Background(), appauth.LoginInput{
		Email:    "nobody@example.com",
		Password: "whatever",
	})
	if !errors.Is(err, appauth.ErrInvalidCredentials) {
		t.Fatalf("Login with unknown email: got %v, want ErrInvalidCredentials (not leak which)", err)
	}
}

// --- Refresh ---

func TestRefresh_RotatesToken(t *testing.T) {
	svc, _, _ := newTestService()
	session := mustRegister(t, svc, "bee@example.com", "supersecret")

	rotated, err := svc.Refresh(context.Background(), session.RefreshToken)
	if err != nil {
		t.Fatalf("Refresh: %v", err)
	}
	if rotated.RefreshToken == session.RefreshToken {
		t.Fatal("Refresh returned the same refresh token instead of rotating it")
	}

	// the old token must no longer work
	if _, err := svc.Refresh(context.Background(), session.RefreshToken); !errors.Is(err, appauth.ErrInvalidRefreshToken) {
		t.Fatalf("reusing rotated-out token: got %v, want ErrInvalidRefreshToken", err)
	}
}

func TestRefresh_ReuseRevokesAllSessions(t *testing.T) {
	svc, _, _ := newTestService()
	session := mustRegister(t, svc, "bee@example.com", "supersecret")

	rotated, err := svc.Refresh(context.Background(), session.RefreshToken)
	if err != nil {
		t.Fatalf("Refresh: %v", err)
	}

	// Replay the original (now revoked) token: this must be treated as
	// theft and kill the entire session family, including the token that
	// was legitimately issued by the rotation above.
	if _, err := svc.Refresh(context.Background(), session.RefreshToken); !errors.Is(err, appauth.ErrInvalidRefreshToken) {
		t.Fatalf("replaying revoked token: got %v, want ErrInvalidRefreshToken", err)
	}

	if _, err := svc.Refresh(context.Background(), rotated.RefreshToken); !errors.Is(err, appauth.ErrInvalidRefreshToken) {
		t.Fatalf("using rotated token after reuse detected: got %v, want ErrInvalidRefreshToken (session family should be dead)", err)
	}
}

func TestRefresh_UnknownToken(t *testing.T) {
	svc, _, _ := newTestService()

	_, err := svc.Refresh(context.Background(), "not-a-real-token")
	if !errors.Is(err, appauth.ErrInvalidRefreshToken) {
		t.Fatalf("Refresh with unknown token: got %v, want ErrInvalidRefreshToken", err)
	}
}

func TestRefresh_ExpiredToken(t *testing.T) {
	users := newFakeUserRepo()
	tokens := newFakeTokenRepo()
	hasher := password.NewBcryptHasher(bcrypt.MinCost)
	issuer := jwtauth.NewIssuer("test-secret", time.Minute)

	// Negative TTL: any refresh token issued by this service is already expired.
	svc := appauth.NewService(users, tokens, hasher, issuer, -time.Hour)

	session := mustRegister(t, svc, "bee@example.com", "supersecret")

	_, err := svc.Refresh(context.Background(), session.RefreshToken)
	if !errors.Is(err, appauth.ErrInvalidRefreshToken) {
		t.Fatalf("Refresh with expired token: got %v, want ErrInvalidRefreshToken", err)
	}
}

// --- Logout ---

func TestLogout_RevokesToken(t *testing.T) {
	svc, _, _ := newTestService()
	session := mustRegister(t, svc, "bee@example.com", "supersecret")

	if err := svc.Logout(context.Background(), session.RefreshToken); err != nil {
		t.Fatalf("Logout: %v", err)
	}

	if _, err := svc.Refresh(context.Background(), session.RefreshToken); !errors.Is(err, appauth.ErrInvalidRefreshToken) {
		t.Fatalf("using logged-out token: got %v, want ErrInvalidRefreshToken", err)
	}
}

func TestLogout_IsIdempotent(t *testing.T) {
	svc, _, _ := newTestService()

	if err := svc.Logout(context.Background(), "unknown-token"); err != nil {
		t.Fatalf("Logout with unknown token: got %v, want nil (idempotent)", err)
	}

	session := mustRegister(t, svc, "bee@example.com", "supersecret")
	if err := svc.Logout(context.Background(), session.RefreshToken); err != nil {
		t.Fatalf("first Logout: %v", err)
	}
	if err := svc.Logout(context.Background(), session.RefreshToken); err != nil {
		t.Fatalf("second Logout: got %v, want nil (idempotent)", err)
	}
}

// --- CurrentUser ---

func TestCurrentUser_Success(t *testing.T) {
	svc, _, _ := newTestService()
	session := mustRegister(t, svc, "bee@example.com", "supersecret")

	u, err := svc.CurrentUser(context.Background(), session.UserID)
	if err != nil {
		t.Fatalf("CurrentUser: %v", err)
	}
	if u.Email != "bee@example.com" {
		t.Errorf("Email = %q, want bee@example.com", u.Email)
	}
}

func TestCurrentUser_NotFound(t *testing.T) {
	svc, _, _ := newTestService()

	_, err := svc.CurrentUser(context.Background(), uuid.New())
	if !errors.Is(err, user.ErrNotFound) {
		t.Fatalf("CurrentUser with unknown ID: got %v, want ErrNotFound", err)
	}
}
