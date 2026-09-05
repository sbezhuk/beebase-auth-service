//go:build integration

package http_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	pquernatotp "github.com/pquerna/otp/totp"
	"golang.org/x/crypto/bcrypt"

	appauth "github.com/sbezhuk/beebase-auth-service/internal/application/auth"
	"github.com/sbezhuk/beebase-auth-service/internal/platform/jwtauth"
	"github.com/sbezhuk/beebase-auth-service/internal/platform/password"
	"github.com/sbezhuk/beebase-auth-service/internal/platform/totpsecret"
	repopostgres "github.com/sbezhuk/beebase-auth-service/internal/repository/postgres"
	transporthttp "github.com/sbezhuk/beebase-auth-service/internal/transport/http"
	authhttp "github.com/sbezhuk/beebase-auth-service/internal/transport/http/auth"
	profilehttp "github.com/sbezhuk/beebase-auth-service/internal/transport/http/profile"

	"github.com/sbezhuk/beebase-common/authmw"
	"github.com/sbezhuk/beebase-common/httpx"
	"github.com/sbezhuk/beebase-common/jwks"
	"github.com/sbezhuk/beebase-common/logger"
)

// stubMediaClient is an in-memory stand-in for media-service, used so
// these HTTP integration tests don't need a real media-service running.
// owned holds the set of media ids VerifyOwnership treats as belonging to
// the caller; anything else is reported as not found, mirroring the real
// client's non-leaking convention.
type stubMediaClient struct {
	owned map[uuid.UUID]bool
}

func newStubMediaClient(owned ...uuid.UUID) *stubMediaClient {
	m := make(map[uuid.UUID]bool, len(owned))
	for _, id := range owned {
		m[id] = true
	}
	return &stubMediaClient{owned: m}
}

func (s *stubMediaClient) VerifyOwnership(_ context.Context, _ string, ids []uuid.UUID) error {
	for _, id := range ids {
		if !s.owned[id] {
			return appauth.ErrAvatarNotFound
		}
	}
	return nil
}

// newTestServer wires a full router against a real PostgreSQL database,
// with every write scoped to a transaction that's rolled back when the
// test ends, so runs never leave rows behind or collide with each other.
// media configures the stubMediaClient's owned media ids (see
// stubMediaClient); most tests that don't touch avatars can leave it
// empty.
func newTestServer(t *testing.T, media ...uuid.UUID) *httptest.Server {
	t.Helper()

	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL not set; skipping HTTP auth integration test")
	}

	pool, err := pgxpool.New(context.Background(), dsn)
	if err != nil {
		t.Fatalf("connect to test database: %v", err)
	}
	t.Cleanup(pool.Close)

	tx, err := pool.Begin(context.Background())
	if err != nil {
		t.Fatalf("begin tx: %v", err)
	}
	t.Cleanup(func() { _ = tx.Rollback(context.Background()) })

	userRepo := repopostgres.NewUserRepository(tx)
	refreshTokenRepo := repopostgres.NewRefreshTokenRepository(tx)
	credentialRepo := repopostgres.NewTwoFactorCredentialRepository(tx)
	loginChallengeRepo := repopostgres.NewLoginChallengeRepository(tx)
	passwordResetFlowRepo := repopostgres.NewPasswordResetFlowRepository(tx)
	hasher := password.NewBcryptHasher(bcrypt.MinCost)

	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	kid := jwtauth.KeyID(pub)
	issuer := jwtauth.NewIssuer(priv, kid, time.Minute)
	verifier := authmw.NewVerifierFromPublicKey(pub)

	jwksHandler, err := jwks.NewHandler(pub, kid)
	if err != nil {
		t.Fatalf("jwks.NewHandler: %v", err)
	}

	cipherKey := make([]byte, totpsecret.KeySize)
	if _, err := rand.Read(cipherKey); err != nil {
		t.Fatalf("generate cipher key: %v", err)
	}
	cipher, err := totpsecret.NewCipher(cipherKey)
	if err != nil {
		t.Fatalf("new cipher: %v", err)
	}

	security := appauth.SecurityConfig{
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

	svc := appauth.NewService(
		userRepo, refreshTokenRepo, credentialRepo, loginChallengeRepo, passwordResetFlowRepo,
		hasher, issuer, newStubMediaClient(media...), cipher, security,
	)
	log := logger.New("development", "error")
	cookieOpts := httpx.CookieOptions{SameSite: http.SameSiteLaxMode}
	handler := authhttp.NewHandler(svc, log, cookieOpts)
	profileHandler := profilehttp.NewHandler(svc, log)

	router := transporthttp.NewRouter(log, pool, handler, profileHandler, verifier, jwksHandler)

	srv := httptest.NewServer(router)
	t.Cleanup(srv.Close)
	return srv
}

// newHTTPClient returns a client with a cookie jar, so the refresh token
// cookie set by register/login/refresh is remembered and replayed
// automatically on subsequent requests, the way a browser would.
func newHTTPClient(t *testing.T) *http.Client {
	t.Helper()

	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatalf("create cookie jar: %v", err)
	}
	return &http.Client{Jar: jar}
}

func postJSON(t *testing.T, client *http.Client, url string, body any) *http.Response {
	t.Helper()

	var reqBody *bytes.Reader
	if body == nil {
		reqBody = bytes.NewReader(nil)
	} else {
		buf, err := json.Marshal(body)
		if err != nil {
			t.Fatalf("marshal request body: %v", err)
		}
		reqBody = bytes.NewReader(buf)
	}

	req, err := http.NewRequest(http.MethodPost, url, reqBody)
	if err != nil {
		t.Fatalf("build POST %s: %v", url, err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("POST %s: %v", url, err)
	}
	return resp
}

// postWithCookie POSTs to url with no body, presenting refreshToken as the
// refresh_token cookie explicitly — used to probe a specific (e.g.
// rotated-out or revoked) token value regardless of what a client's jar
// currently holds.
func postWithCookie(t *testing.T, url, refreshToken string) *http.Response {
	t.Helper()

	req, err := http.NewRequest(http.MethodPost, url, nil)
	if err != nil {
		t.Fatalf("build POST %s: %v", url, err)
	}
	req.AddCookie(&http.Cookie{Name: "refresh_token", Value: refreshToken})

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("POST %s: %v", url, err)
	}
	return resp
}

// refreshCookieValue returns the value of the refresh_token cookie set on
// resp, failing the test if it isn't present.
func refreshCookieValue(t *testing.T, resp *http.Response) string {
	t.Helper()

	for _, c := range resp.Cookies() {
		if c.Name == "refresh_token" {
			return c.Value
		}
	}
	t.Fatal("response did not set a refresh_token cookie")
	return ""
}

func decodeJSON(t *testing.T, resp *http.Response, dst any) {
	t.Helper()
	defer func() { _ = resp.Body.Close() }()

	if err := json.NewDecoder(resp.Body).Decode(dst); err != nil {
		t.Fatalf("decode response body: %v", err)
	}
}

// genCode computes the currently-valid TOTP code for secret, using the
// same underlying library the service itself validates against.
func genCode(t *testing.T, secret string) string {
	t.Helper()
	code, err := pquernatotp.GenerateCode(secret, time.Now().UTC())
	if err != nil {
		t.Fatalf("generate totp code: %v", err)
	}
	return code
}

// genNextCode computes the code for the time-step right after the current
// one - still accepted right now under the server's forward clock-skew
// tolerance, but a distinct time-step counter from genCode's. Use this for
// a second real code against the same account within a test: since BEEB-41
// a counter, once accepted, can never authenticate again, so two genCode
// calls made moments apart (which would otherwise likely collide on the
// same 30s step) must not be presented as if a real user generated them
// separately.
func genNextCode(t *testing.T, secret string) string {
	t.Helper()
	code, err := pquernatotp.GenerateCode(secret, time.Now().UTC().Add(30*time.Second))
	if err != nil {
		t.Fatalf("generate totp code: %v", err)
	}
	return code
}

// registerAndCompleteSetup registers email/password, then immediately
// walks the account through TOTP setup with a correctly-computed code,
// returning both the session /2fa/setup/verify issues and the account's
// TOTP secret (needed by callers that must compute further valid codes,
// e.g. for login or change-password). Registration cannot complete - and
// Login cannot return anything but another setup challenge - without this.
func registerAndCompleteSetup(t *testing.T, client *http.Client, srv *httptest.Server, email, password string) (authhttp.SessionResponse, string) {
	t.Helper()

	resp := postJSON(t, client, srv.URL+"/api/v1/auth/register", map[string]string{
		"email":    email,
		"password": password,
	})
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("register: status = %d, want %d", resp.StatusCode, http.StatusCreated)
	}
	var setup authhttp.TOTPSetupResponse
	decodeJSON(t, resp, &setup)
	if setup.SetupToken == "" || setup.Secret == "" {
		t.Fatal("register: missing setup challenge in response")
	}

	resp = postJSON(t, client, srv.URL+"/api/v1/auth/2fa/setup/verify", map[string]string{
		"setup_token": setup.SetupToken,
		"otp":         genCode(t, setup.Secret),
	})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("2fa/setup/verify: status = %d, want %d", resp.StatusCode, http.StatusOK)
	}
	var session authhttp.SessionResponse
	decodeJSON(t, resp, &session)
	if session.AccessToken == "" {
		t.Fatal("2fa/setup/verify: missing access token in response")
	}
	return session, setup.Secret
}

func TestAuthFlow_RegisterSetupThenMeAndLoginRequireOTP(t *testing.T) {
	srv := newTestServer(t)
	client := newHTTPClient(t)

	session, _ := registerAndCompleteSetup(t, client, srv, "flow@example.com", "supersecret")

	// Me, with the session issued by setup-verify.
	req, _ := http.NewRequest(http.MethodGet, srv.URL+"/api/v1/auth/me", nil)
	req.Header.Set("Authorization", "Bearer "+session.AccessToken)
	meResp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("me: %v", err)
	}
	if meResp.StatusCode != http.StatusOK {
		t.Fatalf("me: status = %d, want %d", meResp.StatusCode, http.StatusOK)
	}
	var me authhttp.UserResponse
	decodeJSON(t, meResp, &me)
	if me.Email != "flow@example.com" {
		t.Errorf("me: email = %q, want flow@example.com", me.Email)
	}

	// Login now returns an OTP challenge, not a session.
	resp := postJSON(t, client, srv.URL+"/api/v1/auth/login", map[string]string{
		"email":    "flow@example.com",
		"password": "supersecret",
	})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("login: status = %d, want %d", resp.StatusCode, http.StatusOK)
	}
	var otpRequired authhttp.LoginOTPRequiredResponse
	decodeJSON(t, resp, &otpRequired)
	if otpRequired.Status != "otp_required" || otpRequired.ChallengeToken == "" {
		t.Fatalf("login: got %+v, want an otp_required challenge", otpRequired)
	}

	// A wrong code must not complete the login.
	resp = postJSON(t, client, srv.URL+"/api/v1/auth/login/verify-otp", map[string]string{
		"challenge_token": otpRequired.ChallengeToken,
		"otp":             "000000",
	})
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("login/verify-otp with wrong code: status = %d, want %d", resp.StatusCode, http.StatusUnauthorized)
	}

	// Logout: the jar presents the refresh_token cookie set by setup-verify.
	resp = postJSON(t, client, srv.URL+"/api/v1/auth/logout", nil)
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("logout: status = %d, want %d", resp.StatusCode, http.StatusNoContent)
	}
}

// TestAuthFlow_FullOTPCycle exercises register -> setup-verify -> login ->
// login/verify-otp -> refresh -> logout end to end with real, correctly
// computed OTP codes throughout, using a harness that keeps the account's
// secret around (unlike registerAndCompleteSetup, which discards it once
// setup is done).
func TestAuthFlow_FullOTPCycle(t *testing.T) {
	srv := newTestServer(t)
	client := newHTTPClient(t)

	resp := postJSON(t, client, srv.URL+"/api/v1/auth/register", map[string]string{
		"email":    "fullcycle@example.com",
		"password": "supersecret",
	})
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("register: status = %d, want %d", resp.StatusCode, http.StatusCreated)
	}
	var setup authhttp.TOTPSetupResponse
	decodeJSON(t, resp, &setup)

	resp = postJSON(t, client, srv.URL+"/api/v1/auth/2fa/setup/verify", map[string]string{
		"setup_token": setup.SetupToken,
		"otp":         genCode(t, setup.Secret),
	})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("2fa/setup/verify: status = %d, want %d", resp.StatusCode, http.StatusOK)
	}

	resp = postJSON(t, client, srv.URL+"/api/v1/auth/login", map[string]string{
		"email":    "fullcycle@example.com",
		"password": "supersecret",
	})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("login: status = %d, want %d", resp.StatusCode, http.StatusOK)
	}
	var otpRequired authhttp.LoginOTPRequiredResponse
	decodeJSON(t, resp, &otpRequired)

	resp = postJSON(t, client, srv.URL+"/api/v1/auth/login/verify-otp", map[string]string{
		"challenge_token": otpRequired.ChallengeToken,
		"otp":             genNextCode(t, setup.Secret),
	})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("login/verify-otp: status = %d, want %d", resp.StatusCode, http.StatusOK)
	}
	loginRefreshToken := refreshCookieValue(t, resp)

	resp = postJSON(t, client, srv.URL+"/api/v1/auth/refresh", nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("refresh: status = %d, want %d", resp.StatusCode, http.StatusOK)
	}
	rotatedRefreshToken := refreshCookieValue(t, resp)
	if rotatedRefreshToken == loginRefreshToken {
		t.Fatal("refresh: token was not rotated")
	}

	resp = postWithCookie(t, srv.URL+"/api/v1/auth/refresh", loginRefreshToken)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("refresh with rotated-out token: status = %d, want %d", resp.StatusCode, http.StatusUnauthorized)
	}

	resp = postJSON(t, client, srv.URL+"/api/v1/auth/logout", nil)
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("logout: status = %d, want %d", resp.StatusCode, http.StatusNoContent)
	}

	resp = postWithCookie(t, srv.URL+"/api/v1/auth/refresh", rotatedRefreshToken)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("refresh after logout: status = %d, want %d", resp.StatusCode, http.StatusUnauthorized)
	}
}

// TestAuthFlow_ChangePasswordRequiresOTP exercises the authenticated
// change-password endpoint, including that neither a wrong current
// password nor a wrong OTP changes anything.
func TestAuthFlow_ChangePasswordRequiresOTP(t *testing.T) {
	srv := newTestServer(t)
	client := newHTTPClient(t)

	session, secret := registerAndCompleteSetup(t, client, srv, "changepw@example.com", "supersecret")

	authedPost := func(url string, body any) *http.Response {
		req, _ := http.NewRequest(http.MethodPost, url, bytes.NewReader(mustMarshal(t, body)))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+session.AccessToken)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("POST %s: %v", url, err)
		}
		return resp
	}

	resp := authedPost(srv.URL+"/api/v1/auth/change-password", map[string]string{
		"current_password": "wrong-password",
		"new_password":     "brandnewpassword",
		"otp":              genCode(t, secret),
	})
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("change-password wrong current password: status = %d, want %d", resp.StatusCode, http.StatusUnauthorized)
	}

	resp = authedPost(srv.URL+"/api/v1/auth/change-password", map[string]string{
		"current_password": "supersecret",
		"new_password":     "brandnewpassword",
		"otp":              "000000",
	})
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("change-password wrong otp: status = %d, want %d", resp.StatusCode, http.StatusUnauthorized)
	}

	resp = authedPost(srv.URL+"/api/v1/auth/change-password", map[string]string{
		"current_password": "supersecret",
		"new_password":     "brandnewpassword",
		"otp":              genNextCode(t, secret),
	})
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("change-password: status = %d, want %d", resp.StatusCode, http.StatusNoContent)
	}

	resp = postJSON(t, client, srv.URL+"/api/v1/auth/login", map[string]string{
		"email":    "changepw@example.com",
		"password": "brandnewpassword",
	})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("login with new password: status = %d, want %d", resp.StatusCode, http.StatusOK)
	}
}

// TestAuthFlow_PasswordResetCycle exercises request -> verify-otp ->
// confirm -> login with the new password, plus confirming the OTP step
// can't be skipped by calling confirm directly.
func TestAuthFlow_PasswordResetCycle(t *testing.T) {
	srv := newTestServer(t)
	client := newHTTPClient(t)

	_, secret := registerAndCompleteSetup(t, client, srv, "forgot@example.com", "supersecret")

	resp := postJSON(t, client, srv.URL+"/api/v1/auth/password-reset/request", map[string]string{
		"email": "forgot@example.com",
	})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("password-reset/request: status = %d, want %d", resp.StatusCode, http.StatusOK)
	}
	var requested authhttp.PasswordResetRequestedResponse
	decodeJSON(t, resp, &requested)
	if requested.FlowToken == "" {
		t.Fatal("password-reset/request: missing flow token")
	}

	// Confirm cannot be reached with only the flow token - OTP must be
	// verified first.
	confirmResp := postJSON(t, client, srv.URL+"/api/v1/auth/password-reset/confirm", map[string]string{
		"reset_token":      requested.FlowToken,
		"new_password":     "brandnewpassword",
		"confirm_password": "brandnewpassword",
	})
	if confirmResp.StatusCode != http.StatusBadRequest {
		t.Fatalf("password-reset/confirm without OTP verify: status = %d, want %d", confirmResp.StatusCode, http.StatusBadRequest)
	}

	resp = postJSON(t, client, srv.URL+"/api/v1/auth/password-reset/verify-otp", map[string]string{
		"flow_token": requested.FlowToken,
		"otp":        genNextCode(t, secret),
	})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("password-reset/verify-otp: status = %d, want %d", resp.StatusCode, http.StatusOK)
	}
	var verified authhttp.PasswordResetOTPVerifiedResponse
	decodeJSON(t, resp, &verified)
	if verified.ResetToken == "" {
		t.Fatal("password-reset/verify-otp: missing reset token")
	}

	resp = postJSON(t, client, srv.URL+"/api/v1/auth/password-reset/confirm", map[string]string{
		"reset_token":      verified.ResetToken,
		"new_password":     "brandnewpassword",
		"confirm_password": "brandnewpassword",
	})
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("password-reset/confirm: status = %d, want %d", resp.StatusCode, http.StatusNoContent)
	}

	resp = postJSON(t, client, srv.URL+"/api/v1/auth/login", map[string]string{
		"email":    "forgot@example.com",
		"password": "brandnewpassword",
	})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("login with new password: status = %d, want %d", resp.StatusCode, http.StatusOK)
	}
}

func mustMarshal(t *testing.T, v any) []byte {
	t.Helper()
	buf, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return buf
}

func TestAuthFlow_RefreshWithoutCookieIsUnauthorized(t *testing.T) {
	srv := newTestServer(t)
	client := newHTTPClient(t)

	resp := postJSON(t, client, srv.URL+"/api/v1/auth/refresh", nil)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("refresh without cookie: status = %d, want %d", resp.StatusCode, http.StatusUnauthorized)
	}
}

func TestAuthFlow_MeWithoutTokenIsUnauthorized(t *testing.T) {
	srv := newTestServer(t)

	resp, err := http.Get(srv.URL + "/api/v1/auth/me")
	if err != nil {
		t.Fatalf("me: %v", err)
	}
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("me without token: status = %d, want %d", resp.StatusCode, http.StatusUnauthorized)
	}
}

func TestAuthFlow_LoginWithWrongPassword(t *testing.T) {
	srv := newTestServer(t)
	client := newHTTPClient(t)

	resp := postJSON(t, client, srv.URL+"/api/v1/auth/register", map[string]string{
		"email":    "wrongpass@example.com",
		"password": "correct-password",
	})
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("register: status = %d, want %d", resp.StatusCode, http.StatusCreated)
	}

	resp = postJSON(t, client, srv.URL+"/api/v1/auth/login", map[string]string{
		"email":    "wrongpass@example.com",
		"password": "wrong-password",
	})
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("login with wrong password: status = %d, want %d", resp.StatusCode, http.StatusUnauthorized)
	}
}
