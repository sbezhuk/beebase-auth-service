package auth_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	pquernatotp "github.com/pquerna/otp/totp"
	"golang.org/x/crypto/bcrypt"

	appauth "github.com/sbezhuk/beebase-auth-service/internal/application/auth"
	"github.com/sbezhuk/beebase-auth-service/internal/domain/token"
	"github.com/sbezhuk/beebase-auth-service/internal/domain/user"
	"github.com/sbezhuk/beebase-auth-service/internal/platform/jwtauth"
	"github.com/sbezhuk/beebase-auth-service/internal/platform/password"
	"github.com/sbezhuk/beebase-auth-service/internal/platform/totpsecret"
)

// newTestIssuer builds an Issuer with a freshly generated key. Key
// generation only fails if crypto/rand itself is broken, which would make
// every other test in this process meaningless too, so this panics rather
// than threading a *testing.T through every call site.
func newTestIssuer(ttl time.Duration) *jwtauth.Issuer {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		panic(err)
	}
	return jwtauth.NewIssuer(priv, jwtauth.KeyID(pub), ttl)
}

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

func (f *fakeUserRepo) Update(_ context.Context, u *user.User) error {
	f.mu.Lock()
	defer f.mu.Unlock()

	if _, ok := f.byID[u.ID]; !ok {
		return user.ErrNotFound
	}

	cp := *u
	f.byID[u.ID] = &cp
	f.byEmail[u.Email] = &cp
	return nil
}

func (f *fakeUserRepo) UpdatePassword(_ context.Context, id uuid.UUID, passwordHash string) error {
	f.mu.Lock()
	defer f.mu.Unlock()

	u, ok := f.byID[id]
	if !ok {
		return user.ErrNotFound
	}

	u.PasswordHash = passwordHash
	u.UpdatedAt = time.Now().UTC()
	f.byEmail[u.Email] = u
	return nil
}

func (f *fakeUserRepo) Delete(_ context.Context, id uuid.UUID) error {
	f.mu.Lock()
	defer f.mu.Unlock()

	u, ok := f.byID[id]
	if !ok {
		return user.ErrNotFound
	}

	delete(f.byID, id)
	delete(f.byEmail, u.Email)
	return nil
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

// fakeMediaClient is an in-memory stand-in for media-service. owned holds
// the set of media ids VerifyOwnership treats as belonging to the caller;
// anything else is reported as not found, mirroring the real client's
// non-leaking convention. deleteAllErr, when set, makes DeleteAllByUser
// fail - used to exercise DeleteAccount's abort-on-failure behavior.
type fakeMediaClient struct {
	owned           map[uuid.UUID]bool
	deleteAllCalled bool
	deleteAllErr    error
}

func newFakeMediaClient(owned ...uuid.UUID) *fakeMediaClient {
	m := make(map[uuid.UUID]bool, len(owned))
	for _, id := range owned {
		m[id] = true
	}
	return &fakeMediaClient{owned: m}
}

func (f *fakeMediaClient) VerifyOwnership(_ context.Context, _ string, ids []uuid.UUID) error {
	for _, id := range ids {
		if !f.owned[id] {
			return appauth.ErrAvatarNotFound
		}
	}
	return nil
}

func (f *fakeMediaClient) DeleteAllByUser(_ context.Context, _ string) error {
	if f.deleteAllErr != nil {
		return f.deleteAllErr
	}
	f.deleteAllCalled = true
	return nil
}

// fakeApiaryDeleter is an in-memory stand-in for apiary-service, mirroring
// application/auth.ApiaryCascadeDeleter. It records whether it was called
// and can be configured to fail, to exercise DeleteAccount's
// abort-on-failure behavior.
type fakeApiaryDeleter struct {
	called  bool
	failErr error
}

func (f *fakeApiaryDeleter) DeleteAllMine(_ context.Context, _ string) error {
	if f.failErr != nil {
		return f.failErr
	}
	f.called = true
	return nil
}

// --- test harness ---

// newTestCipher builds a totpsecret.Cipher with a freshly generated random
// key. As with newTestIssuer, a key-generation failure would make every
// other test meaningless too, so this panics rather than threading a
// *testing.T through every call site.
func newTestCipher() *totpsecret.Cipher {
	key := make([]byte, totpsecret.KeySize)
	if _, err := rand.Read(key); err != nil {
		panic(err)
	}
	c, err := totpsecret.NewCipher(key)
	if err != nil {
		panic(err)
	}
	return c
}

// newTestSecurityConfig returns generous TTLs (so tests never race a
// clock) and a small attempt cap (so lockout tests don't need long loops).
func newTestSecurityConfig() appauth.SecurityConfig {
	return appauth.SecurityConfig{
		RefreshTTL:              time.Hour,
		SetupTokenTTL:           time.Hour,
		LoginChallengeTTL:       time.Hour,
		PasswordResetFlowTTL:    time.Hour,
		PasswordResetTokenTTL:   time.Hour,
		OTPMaxAttempts:          5,
		OTPLockoutDuration:      15 * time.Minute,
		ResetFlowMaxOTPAttempts: 5,
		TOTPIssuer:              "BeeBase Test",
	}
}

// genCode computes the currently-valid TOTP code for secret, by calling
// the same underlying library the service itself uses - the same "use the
// real thing" approach this file already takes for bcrypt and ed25519.
func genCode(t *testing.T, secret string) string {
	t.Helper()
	return genCodeAt(t, secret, time.Now().UTC())
}

// genNextCode computes the code for the time-step right after the current
// one. Validate's forward clock-skew tolerance still accepts it right now,
// but it's a distinct time-step counter from genCode's - use this for a
// second real validation against the same credential within a test, since
// BEEB-41's anti-replay fix means a counter, once accepted, can never
// authenticate again (so two genCode calls made moments apart, which would
// normally collide on the same 30s step, must not be presented as if a
// real user generated them separately).
func genNextCode(t *testing.T, secret string) string {
	t.Helper()
	return genCodeAt(t, secret, time.Now().UTC().Add(30*time.Second))
}

func genCodeAt(t *testing.T, secret string, at time.Time) string {
	t.Helper()
	code, err := pquernatotp.GenerateCode(secret, at)
	if err != nil {
		t.Fatalf("generate totp code: %v", err)
	}
	return code
}

func newTestService() (*appauth.Service, *fakeUserRepo, *fakeTokenRepo) {
	svc, users, tokens, _ := newTestServiceWithMedia()
	return svc, users, tokens
}

func newTestServiceWithMedia(owned ...uuid.UUID) (*appauth.Service, *fakeUserRepo, *fakeTokenRepo, *fakeMediaClient) {
	users := newFakeUserRepo()
	tokens := newFakeTokenRepo()
	credentials := newFakeCredentialRepo()
	challenges := newFakeLoginChallengeRepo()
	resetFlows := newFakePasswordResetFlowRepo()
	hasher := password.NewBcryptHasher(bcrypt.MinCost)
	issuer := newTestIssuer(time.Minute)
	media := newFakeMediaClient(owned...)
	cipher := newTestCipher()

	svc := appauth.NewService(users, tokens, credentials, challenges, resetFlows, hasher, issuer, media, &fakeApiaryDeleter{}, cipher, newTestSecurityConfig())
	return svc, users, tokens, media
}

// mustRegister creates an account and walks it all the way through TOTP
// setup, returning the session SetupVerifyOTP issues on success -
// registration cannot complete, and Login cannot return anything but a
// setup challenge, without this.
func mustRegister(t *testing.T, svc *appauth.Service, email, pw string) *appauth.Session {
	t.Helper()

	setup, err := svc.Register(context.Background(), appauth.RegisterInput{Email: email, Password: pw})
	if err != nil {
		t.Fatalf("Register: %v", err)
	}

	session, err := svc.SetupVerifyOTP(context.Background(), setup.SetupToken, genCode(t, setup.Secret))
	if err != nil {
		t.Fatalf("SetupVerifyOTP: %v", err)
	}
	return session
}

// --- Register ---

func TestRegister_ReturnsSetupChallenge_NotASession(t *testing.T) {
	svc, _, _ := newTestService()

	result, err := svc.Register(context.Background(), appauth.RegisterInput{Email: "Bee@Example.com", Password: "supersecret"})
	if err != nil {
		t.Fatalf("Register: %v", err)
	}
	if result.SetupToken == "" || result.OtpauthURI == "" || result.Secret == "" {
		t.Fatal("Register did not return a full TOTP setup challenge")
	}
}

func TestRegister_DuplicateEmail(t *testing.T) {
	svc, _, _ := newTestService()
	if _, err := svc.Register(context.Background(), appauth.RegisterInput{Email: "bee@example.com", Password: "supersecret"}); err != nil {
		t.Fatalf("Register: %v", err)
	}

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
	if _, err := svc.Register(context.Background(), appauth.RegisterInput{Email: "bee@example.com", Password: "supersecret"}); err != nil {
		t.Fatalf("Register: %v", err)
	}

	_, err := svc.Register(context.Background(), appauth.RegisterInput{
		Email:    "BEE@EXAMPLE.COM",
		Password: "anotherpassword",
	})
	if !errors.Is(err, user.ErrEmailTaken) {
		t.Fatalf("Register with same email different case: got %v, want ErrEmailTaken", err)
	}
}

// TestRegister_DuplicateEmailNeverOverwritesPassword guards against a real
// account-takeover bug considered during design: a second /register call
// against an email that's still pending 2FA setup must never be able to
// silently take over the account by supplying a different password, since
// the caller has proven nothing about knowing the original one.
func TestRegister_DuplicateEmailNeverOverwritesPassword(t *testing.T) {
	svc, _, _ := newTestService()
	if _, err := svc.Register(context.Background(), appauth.RegisterInput{Email: "bee@example.com", Password: "supersecret"}); err != nil {
		t.Fatalf("Register: %v", err)
	}

	if _, err := svc.Register(context.Background(), appauth.RegisterInput{
		Email:    "bee@example.com",
		Password: "attacker-password",
	}); !errors.Is(err, user.ErrEmailTaken) {
		t.Fatalf("Register with duplicate email: got %v, want ErrEmailTaken", err)
	}

	if _, err := svc.Login(context.Background(), appauth.LoginInput{Email: "bee@example.com", Password: "attacker-password"}); !errors.Is(err, appauth.ErrInvalidCredentials) {
		t.Fatalf("Login with attacker's password: got %v, want ErrInvalidCredentials", err)
	}

	result, err := svc.Login(context.Background(), appauth.LoginInput{Email: "bee@example.com", Password: "supersecret"})
	if err != nil {
		t.Fatalf("Login with original password: %v", err)
	}
	if result.Status != appauth.LoginStatusTOTPSetupRequired {
		t.Fatalf("Login status = %v, want LoginStatusTOTPSetupRequired", result.Status)
	}
}

// --- Login ---

func TestLogin_EnabledAccount_ReturnsOTPRequired_NoSessionIssued(t *testing.T) {
	svc, _, _ := newTestService()
	mustRegister(t, svc, "bee@example.com", "supersecret")

	result, err := svc.Login(context.Background(), appauth.LoginInput{
		Email:    "bee@example.com",
		Password: "supersecret",
	})
	if err != nil {
		t.Fatalf("Login: %v", err)
	}
	if result.Status != appauth.LoginStatusOTPRequired {
		t.Fatalf("Status = %v, want LoginStatusOTPRequired", result.Status)
	}
	if result.ChallengeToken == "" {
		t.Error("Login did not issue a challenge token")
	}
}

func TestLogin_UnverifiedAccount_ReturnsSetupRequired_RegeneratesSecret(t *testing.T) {
	svc, _, _ := newTestService()
	registered, err := svc.Register(context.Background(), appauth.RegisterInput{Email: "bee@example.com", Password: "supersecret"})
	if err != nil {
		t.Fatalf("Register: %v", err)
	}

	result, err := svc.Login(context.Background(), appauth.LoginInput{Email: "bee@example.com", Password: "supersecret"})
	if err != nil {
		t.Fatalf("Login: %v", err)
	}
	if result.Status != appauth.LoginStatusTOTPSetupRequired {
		t.Fatalf("Status = %v, want LoginStatusTOTPSetupRequired", result.Status)
	}
	if result.SetupToken == "" || result.Secret == "" {
		t.Fatal("Login did not issue a fresh setup challenge")
	}
	if result.SetupToken == registered.SetupToken {
		t.Error("Login reused Register's setup token instead of regenerating one")
	}

	// The original setup token must no longer work, since it was replaced.
	if _, err := svc.SetupVerifyOTP(context.Background(), registered.SetupToken, genCode(t, registered.Secret)); !errors.Is(err, appauth.ErrSetupTokenInvalid) {
		t.Fatalf("SetupVerifyOTP with superseded token: got %v, want ErrSetupTokenInvalid", err)
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
	credentials := newFakeCredentialRepo()
	challenges := newFakeLoginChallengeRepo()
	resetFlows := newFakePasswordResetFlowRepo()
	hasher := password.NewBcryptHasher(bcrypt.MinCost)
	issuer := newTestIssuer(time.Minute)

	// Negative TTL: any refresh token issued by this service is already expired.
	security := newTestSecurityConfig()
	security.RefreshTTL = -time.Hour
	svc := appauth.NewService(users, tokens, credentials, challenges, resetFlows, hasher, issuer, newFakeMediaClient(), &fakeApiaryDeleter{}, newTestCipher(), security)

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

// --- UpdateProfile ---

func TestUpdateProfile_SetsNameAndAvatar(t *testing.T) {
	avatarID := uuid.New()
	svc, _, _, _ := newTestServiceWithMedia(avatarID)
	session := mustRegister(t, svc, "bee@example.com", "supersecret")

	updated, err := svc.UpdateProfile(context.Background(), session.UserID, "access-token", appauth.UpdateProfileInput{
		FirstName: "Jane",
		LastName:  "Doe",
		Avatar:    &appauth.AvatarChange{MediaID: &avatarID},
	})
	if err != nil {
		t.Fatalf("UpdateProfile: %v", err)
	}
	if updated.FirstName != "Jane" || updated.LastName != "Doe" {
		t.Errorf("name = %q %q, want Jane Doe", updated.FirstName, updated.LastName)
	}
	if updated.AvatarMediaID == nil || *updated.AvatarMediaID != avatarID {
		t.Errorf("AvatarMediaID = %v, want %v", updated.AvatarMediaID, avatarID)
	}

	// Persisted, not just returned.
	got, err := svc.CurrentUser(context.Background(), session.UserID)
	if err != nil {
		t.Fatalf("CurrentUser: %v", err)
	}
	if got.FirstName != "Jane" || got.AvatarMediaID == nil || *got.AvatarMediaID != avatarID {
		t.Fatalf("CurrentUser after UpdateProfile did not reflect the change: %+v", got)
	}
}

func TestUpdateProfile_UnownedAvatarIsRejected(t *testing.T) {
	svc, _, _, _ := newTestServiceWithMedia() // owns nothing
	session := mustRegister(t, svc, "bee@example.com", "supersecret")

	someoneElsesMedia := uuid.New()
	_, err := svc.UpdateProfile(context.Background(), session.UserID, "access-token", appauth.UpdateProfileInput{
		FirstName: "Jane",
		LastName:  "Doe",
		Avatar:    &appauth.AvatarChange{MediaID: &someoneElsesMedia},
	})
	if !errors.Is(err, appauth.ErrAvatarNotFound) {
		t.Fatalf("UpdateProfile with unowned avatar: got %v, want ErrAvatarNotFound", err)
	}
}

func TestUpdateProfile_AvatarUntouchedWhenNil(t *testing.T) {
	avatarID := uuid.New()
	svc, _, _, _ := newTestServiceWithMedia(avatarID)
	session := mustRegister(t, svc, "bee@example.com", "supersecret")

	if _, err := svc.UpdateProfile(context.Background(), session.UserID, "access-token", appauth.UpdateProfileInput{
		FirstName: "Jane",
		LastName:  "Doe",
		Avatar:    &appauth.AvatarChange{MediaID: &avatarID},
	}); err != nil {
		t.Fatalf("first UpdateProfile: %v", err)
	}

	// A second update that omits Avatar entirely must leave it alone.
	updated, err := svc.UpdateProfile(context.Background(), session.UserID, "access-token", appauth.UpdateProfileInput{
		FirstName: "Janet",
		LastName:  "Doe",
	})
	if err != nil {
		t.Fatalf("second UpdateProfile: %v", err)
	}
	if updated.AvatarMediaID == nil || *updated.AvatarMediaID != avatarID {
		t.Errorf("AvatarMediaID = %v, want untouched %v", updated.AvatarMediaID, avatarID)
	}
}

func TestUpdateProfile_AvatarRemoved(t *testing.T) {
	avatarID := uuid.New()
	svc, _, _, _ := newTestServiceWithMedia(avatarID)
	session := mustRegister(t, svc, "bee@example.com", "supersecret")

	if _, err := svc.UpdateProfile(context.Background(), session.UserID, "access-token", appauth.UpdateProfileInput{
		FirstName: "Jane",
		LastName:  "Doe",
		Avatar:    &appauth.AvatarChange{MediaID: &avatarID},
	}); err != nil {
		t.Fatalf("first UpdateProfile: %v", err)
	}

	// An explicit AvatarChange with a nil MediaID removes it.
	updated, err := svc.UpdateProfile(context.Background(), session.UserID, "access-token", appauth.UpdateProfileInput{
		FirstName: "Jane",
		LastName:  "Doe",
		Avatar:    &appauth.AvatarChange{},
	})
	if err != nil {
		t.Fatalf("second UpdateProfile: %v", err)
	}
	if updated.AvatarMediaID != nil {
		t.Errorf("AvatarMediaID = %v, want nil after removal", updated.AvatarMediaID)
	}
}

func TestUpdateProfile_NotFound(t *testing.T) {
	svc, _, _, _ := newTestServiceWithMedia()

	_, err := svc.UpdateProfile(context.Background(), uuid.New(), "access-token", appauth.UpdateProfileInput{
		FirstName: "Jane",
		LastName:  "Doe",
	})
	if !errors.Is(err, user.ErrNotFound) {
		t.Fatalf("UpdateProfile for unknown user: got %v, want ErrNotFound", err)
	}
}

// newTestServiceForDelete builds a Service backed by fresh, directly
// inspectable fakes for the two cascade dependencies DeleteAccount drives
// (apiary-service and media-service), so a test can assert both were
// actually called - or, for the abort-on-failure tests, that a later one
// never was.
func newTestServiceForDelete() (svc *appauth.Service, users *fakeUserRepo, media *fakeMediaClient, apiaries *fakeApiaryDeleter) {
	users = newFakeUserRepo()
	tokens := newFakeTokenRepo()
	credentials := newFakeCredentialRepo()
	challenges := newFakeLoginChallengeRepo()
	resetFlows := newFakePasswordResetFlowRepo()
	hasher := password.NewBcryptHasher(bcrypt.MinCost)
	issuer := newTestIssuer(time.Minute)
	media = newFakeMediaClient()
	apiaries = &fakeApiaryDeleter{}
	cipher := newTestCipher()

	svc = appauth.NewService(users, tokens, credentials, challenges, resetFlows, hasher, issuer, media, apiaries, cipher, newTestSecurityConfig())
	return svc, users, media, apiaries
}

// TestDeleteAccount_Success proves the full cascade: apiary-service is
// asked to delete every apiary the caller owns (which, transitively,
// already reaches their hives, inspections, and media), then
// media-service is swept for anything left over (e.g. an avatar), then
// the user row itself is removed.
func TestDeleteAccount_Success(t *testing.T) {
	svc, _, media, apiaries := newTestServiceForDelete()
	session := mustRegister(t, svc, "bee@example.com", "supersecret")

	if err := svc.DeleteAccount(context.Background(), session.UserID, "access-token"); err != nil {
		t.Fatalf("DeleteAccount: %v", err)
	}

	if !apiaries.called {
		t.Error("DeleteAccount did not cascade to apiary-service")
	}
	if !media.deleteAllCalled {
		t.Error("DeleteAccount did not sweep media-service")
	}
	if _, err := svc.CurrentUser(context.Background(), session.UserID); !errors.Is(err, user.ErrNotFound) {
		t.Fatalf("CurrentUser after DeleteAccount: got %v, want ErrNotFound", err)
	}
}

func TestDeleteAccount_UnknownUser(t *testing.T) {
	svc, _, media, apiaries := newTestServiceForDelete()

	if err := svc.DeleteAccount(context.Background(), uuid.New(), "access-token"); !errors.Is(err, user.ErrNotFound) {
		t.Fatalf("DeleteAccount for unknown user: got %v, want ErrNotFound", err)
	}
	if apiaries.called || media.deleteAllCalled {
		t.Error("DeleteAccount must not call downstream services for a user that doesn't exist")
	}
}

// TestDeleteAccount_AbortsOnApiaryCascadeFailure_AccountSurvives is the
// core abort-on-failure guarantee: if apiary-service can't be reached (or
// fails for any other reason), the account itself must not be deleted -
// otherwise its apiaries (and their hives/inspections/media) would be
// permanently orphaned, unreachable through any API but never actually
// removed.
func TestDeleteAccount_AbortsOnApiaryCascadeFailure_AccountSurvives(t *testing.T) {
	svc, _, media, apiaries := newTestServiceForDelete()
	session := mustRegister(t, svc, "bee@example.com", "supersecret")

	boom := errors.New("apiary-service unreachable")
	apiaries.failErr = boom

	if err := svc.DeleteAccount(context.Background(), session.UserID, "access-token"); !errors.Is(err, boom) {
		t.Fatalf("DeleteAccount: got %v, want %v", err, boom)
	}

	if media.deleteAllCalled {
		t.Error("media-service was called even though apiary-service failed first")
	}
	if _, err := svc.CurrentUser(context.Background(), session.UserID); err != nil {
		t.Fatalf("account should survive when apiary-service fails: %v", err)
	}
}

// TestDeleteAccount_AbortsOnMediaSweepFailure_AccountSurvives mirrors the
// previous test for the second cascade step: media-service failing must
// also stop the account itself from being deleted, even though
// apiary-service's step already succeeded.
func TestDeleteAccount_AbortsOnMediaSweepFailure_AccountSurvives(t *testing.T) {
	svc, _, media, apiaries := newTestServiceForDelete()
	session := mustRegister(t, svc, "bee@example.com", "supersecret")

	boom := errors.New("media-service unreachable")
	media.deleteAllErr = boom

	if err := svc.DeleteAccount(context.Background(), session.UserID, "access-token"); !errors.Is(err, boom) {
		t.Fatalf("DeleteAccount: got %v, want %v", err, boom)
	}

	if !apiaries.called {
		t.Error("apiary-service should have already been called before media-service failed")
	}
	if _, err := svc.CurrentUser(context.Background(), session.UserID); err != nil {
		t.Fatalf("account should survive when media-service fails: %v", err)
	}
}
