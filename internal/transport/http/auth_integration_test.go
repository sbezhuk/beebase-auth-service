//go:build integration

package http_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"golang.org/x/crypto/bcrypt"

	appauth "github.com/sbezhuk/beebase-auth-service/internal/application/auth"
	"github.com/sbezhuk/beebase-auth-service/internal/platform/jwtauth"
	"github.com/sbezhuk/beebase-auth-service/internal/platform/password"
	repopostgres "github.com/sbezhuk/beebase-auth-service/internal/repository/postgres"
	transporthttp "github.com/sbezhuk/beebase-auth-service/internal/transport/http"
	authhttp "github.com/sbezhuk/beebase-auth-service/internal/transport/http/auth"

	"github.com/sbezhuk/beebase-common/authmw"
	"github.com/sbezhuk/beebase-common/httpx"
	"github.com/sbezhuk/beebase-common/jwks"
	"github.com/sbezhuk/beebase-common/logger"
)

// newTestServer wires a full router against a real PostgreSQL database,
// with every write scoped to a transaction that's rolled back when the
// test ends, so runs never leave rows behind or collide with each other.
func newTestServer(t *testing.T) *httptest.Server {
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

	svc := appauth.NewService(userRepo, refreshTokenRepo, hasher, issuer, time.Hour)
	log := logger.New("development", "error")
	cookieOpts := httpx.CookieOptions{SameSite: http.SameSiteLaxMode}
	handler := authhttp.NewHandler(svc, log, cookieOpts)

	router := transporthttp.NewRouter(log, pool, handler, verifier, jwksHandler)

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

func TestAuthFlow_RegisterLoginRefreshLogoutMe(t *testing.T) {
	srv := newTestServer(t)
	client := newHTTPClient(t)

	var session authhttp.SessionResponse

	// Register
	resp := postJSON(t, client, srv.URL+"/api/v1/auth/register", map[string]string{
		"email":    "flow@example.com",
		"password": "supersecret",
	})
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("register: status = %d, want %d", resp.StatusCode, http.StatusCreated)
	}
	decodeJSON(t, resp, &session)
	if session.AccessToken == "" {
		t.Fatal("register: missing access token in response")
	}
	if refreshCookieValue(t, resp) == "" {
		t.Fatal("register: empty refresh_token cookie")
	}

	// Me, with the freshly issued access token
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

	// Login: the client's jar now holds login's refresh_token cookie,
	// replacing register's.
	resp = postJSON(t, client, srv.URL+"/api/v1/auth/login", map[string]string{
		"email":    "flow@example.com",
		"password": "supersecret",
	})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("login: status = %d, want %d", resp.StatusCode, http.StatusOK)
	}
	loginRefreshToken := refreshCookieValue(t, resp)

	// Refresh: the jar automatically presents login's refresh_token cookie;
	// the response rotates it to a new value.
	resp = postJSON(t, client, srv.URL+"/api/v1/auth/refresh", nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("refresh: status = %d, want %d", resp.StatusCode, http.StatusOK)
	}
	rotatedRefreshToken := refreshCookieValue(t, resp)
	if rotatedRefreshToken == loginRefreshToken {
		t.Fatal("refresh: token was not rotated")
	}

	// The old (rotated-out) refresh token must now be rejected.
	resp = postWithCookie(t, srv.URL+"/api/v1/auth/refresh", loginRefreshToken)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("refresh with rotated-out token: status = %d, want %d", resp.StatusCode, http.StatusUnauthorized)
	}

	// Logout: the jar presents the current (rotated) refresh_token cookie.
	resp = postJSON(t, client, srv.URL+"/api/v1/auth/logout", nil)
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("logout: status = %d, want %d", resp.StatusCode, http.StatusNoContent)
	}

	// The logged-out refresh token must no longer work.
	resp = postWithCookie(t, srv.URL+"/api/v1/auth/refresh", rotatedRefreshToken)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("refresh after logout: status = %d, want %d", resp.StatusCode, http.StatusUnauthorized)
	}
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
