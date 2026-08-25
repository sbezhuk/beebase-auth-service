//go:build integration

package http_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"net/http"
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
	handler := authhttp.NewHandler(svc, log)

	router := transporthttp.NewRouter(log, pool, handler, verifier, jwksHandler)

	srv := httptest.NewServer(router)
	t.Cleanup(srv.Close)
	return srv
}

func postJSON(t *testing.T, url string, body any) *http.Response {
	t.Helper()

	buf, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("marshal request body: %v", err)
	}

	resp, err := http.Post(url, "application/json", bytes.NewReader(buf))
	if err != nil {
		t.Fatalf("POST %s: %v", url, err)
	}
	return resp
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

	var session authhttp.SessionResponse

	// Register
	resp := postJSON(t, srv.URL+"/api/v1/auth/register", map[string]string{
		"email":    "flow@example.com",
		"password": "supersecret",
	})
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("register: status = %d, want %d", resp.StatusCode, http.StatusCreated)
	}
	decodeJSON(t, resp, &session)
	if session.AccessToken == "" || session.RefreshToken == "" {
		t.Fatal("register: missing tokens in response")
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

	// Login
	resp = postJSON(t, srv.URL+"/api/v1/auth/login", map[string]string{
		"email":    "flow@example.com",
		"password": "supersecret",
	})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("login: status = %d, want %d", resp.StatusCode, http.StatusOK)
	}
	var loginSession authhttp.SessionResponse
	decodeJSON(t, resp, &loginSession)

	// Refresh: rotates the refresh token issued at login
	resp = postJSON(t, srv.URL+"/api/v1/auth/refresh", map[string]string{
		"refresh_token": loginSession.RefreshToken,
	})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("refresh: status = %d, want %d", resp.StatusCode, http.StatusOK)
	}
	var refreshed authhttp.SessionResponse
	decodeJSON(t, resp, &refreshed)
	if refreshed.RefreshToken == loginSession.RefreshToken {
		t.Fatal("refresh: token was not rotated")
	}

	// The old (rotated-out) refresh token must now be rejected.
	resp = postJSON(t, srv.URL+"/api/v1/auth/refresh", map[string]string{
		"refresh_token": loginSession.RefreshToken,
	})
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("refresh with rotated-out token: status = %d, want %d", resp.StatusCode, http.StatusUnauthorized)
	}

	// Logout with the current (rotated) refresh token.
	resp = postJSON(t, srv.URL+"/api/v1/auth/logout", map[string]string{
		"refresh_token": refreshed.RefreshToken,
	})
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("logout: status = %d, want %d", resp.StatusCode, http.StatusNoContent)
	}

	// The logged-out refresh token must no longer work.
	resp = postJSON(t, srv.URL+"/api/v1/auth/refresh", map[string]string{
		"refresh_token": refreshed.RefreshToken,
	})
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("refresh after logout: status = %d, want %d", resp.StatusCode, http.StatusUnauthorized)
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

	resp := postJSON(t, srv.URL+"/api/v1/auth/register", map[string]string{
		"email":    "wrongpass@example.com",
		"password": "correct-password",
	})
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("register: status = %d, want %d", resp.StatusCode, http.StatusCreated)
	}

	resp = postJSON(t, srv.URL+"/api/v1/auth/login", map[string]string{
		"email":    "wrongpass@example.com",
		"password": "wrong-password",
	})
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("login with wrong password: status = %d, want %d", resp.StatusCode, http.StatusUnauthorized)
	}
}
