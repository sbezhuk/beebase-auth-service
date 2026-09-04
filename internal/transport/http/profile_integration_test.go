//go:build integration

package http_test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/google/uuid"

	profilehttp "github.com/sbezhuk/beebase-auth-service/internal/transport/http/profile"
)

// doProfileRequest builds and sends an authenticated request against the
// profile endpoints. body, when non-nil, is marshaled as the JSON request
// body; pass nil for GET.
func doProfileRequest(t *testing.T, method, url, accessToken string, body any) *http.Response {
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

	req, err := http.NewRequest(method, url, reqBody)
	if err != nil {
		t.Fatalf("build %s %s: %v", method, url, err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+accessToken)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, url, err)
	}
	return resp
}

func TestProfileFlow_GetAndUpdate(t *testing.T) {
	avatarID := uuid.New()
	srv := newTestServer(t, avatarID)

	client := newHTTPClient(t)
	session, _ := registerAndCompleteSetup(t, client, srv, "profile-flow@example.com", "supersecret")

	// GET before any edit: empty name, no avatar.
	getResp := doProfileRequest(t, http.MethodGet, srv.URL+"/api/v1/profile", session.AccessToken, nil)
	if getResp.StatusCode != http.StatusOK {
		t.Fatalf("get profile: status = %d, want %d", getResp.StatusCode, http.StatusOK)
	}
	var got profilehttp.Response
	decodeJSON(t, getResp, &got)
	if got.Email != "profile-flow@example.com" {
		t.Errorf("email = %q, want profile-flow@example.com", got.Email)
	}
	if got.Avatar != nil {
		t.Errorf("avatar = %v, want nil before any update", got.Avatar)
	}

	// PUT: set name and avatar.
	avatarStr := avatarID.String()
	putResp := doProfileRequest(t, http.MethodPut, srv.URL+"/api/v1/profile", session.AccessToken, map[string]any{
		"firstName": "Jane",
		"lastName":  "Doe",
		"avatar":    avatarStr,
	})
	if putResp.StatusCode != http.StatusOK {
		t.Fatalf("update profile: status = %d, want %d", putResp.StatusCode, http.StatusOK)
	}
	var updated profilehttp.Response
	decodeJSON(t, putResp, &updated)
	if updated.FirstName != "Jane" || updated.LastName != "Doe" {
		t.Errorf("name = %q %q, want Jane Doe", updated.FirstName, updated.LastName)
	}
	if updated.Avatar == nil || *updated.Avatar != avatarID {
		t.Errorf("avatar = %v, want %v", updated.Avatar, avatarID)
	}

	// GET again: the change persisted.
	getResp2 := doProfileRequest(t, http.MethodGet, srv.URL+"/api/v1/profile", session.AccessToken, nil)
	var got2 profilehttp.Response
	decodeJSON(t, getResp2, &got2)
	if got2.FirstName != "Jane" {
		t.Errorf("persisted first name = %q, want Jane", got2.FirstName)
	}
}

func TestProfileFlow_CannotUpdateAnotherUsersProfile(t *testing.T) {
	srv := newTestServer(t)
	client := newHTTPClient(t)

	// Register two accounts.
	session1, _ := registerAndCompleteSetup(t, client, srv, "user-one@example.com", "supersecret")

	client2 := newHTTPClient(t)
	session2, _ := registerAndCompleteSetup(t, client2, srv, "user-two@example.com", "supersecret")

	// user-one updates their own profile.
	putResp := doProfileRequest(t, http.MethodPut, srv.URL+"/api/v1/profile", session1.AccessToken, map[string]any{
		"firstName": "One",
		"lastName":  "First",
	})
	if putResp.StatusCode != http.StatusOK {
		t.Fatalf("update own profile: status = %d, want %d", putResp.StatusCode, http.StatusOK)
	}

	// user-two's profile must be untouched - there is no way to target
	// another user's profile through this endpoint at all (the target is
	// always the caller's own verified access token), so this simply
	// verifies user-two still sees their own, unmodified data.
	getResp := doProfileRequest(t, http.MethodGet, srv.URL+"/api/v1/profile", session2.AccessToken, nil)
	var got profilehttp.Response
	decodeJSON(t, getResp, &got)
	if got.FirstName != "" {
		t.Errorf("user-two's first name = %q, want untouched empty string", got.FirstName)
	}
	if got.Email != "user-two@example.com" {
		t.Errorf("user-two's email = %q, want user-two@example.com", got.Email)
	}
}

func TestProfileFlow_GetWithoutTokenIsUnauthorized(t *testing.T) {
	srv := newTestServer(t)

	resp, err := http.Get(srv.URL + "/api/v1/profile")
	if err != nil {
		t.Fatalf("get profile: %v", err)
	}
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("get profile without token: status = %d, want %d", resp.StatusCode, http.StatusUnauthorized)
	}
}

func TestProfileFlow_UpdateWithUnownedAvatarIsRejected(t *testing.T) {
	srv := newTestServer(t) // stub media client owns nothing
	client := newHTTPClient(t)

	session, _ := registerAndCompleteSetup(t, client, srv, "unowned-avatar@example.com", "supersecret")

	putResp := doProfileRequest(t, http.MethodPut, srv.URL+"/api/v1/profile", session.AccessToken, map[string]any{
		"firstName": "Jane",
		"lastName":  "Doe",
		"avatar":    uuid.New().String(),
	})
	if putResp.StatusCode != http.StatusBadRequest {
		t.Fatalf("update with unowned avatar: status = %d, want %d", putResp.StatusCode, http.StatusBadRequest)
	}
}

func TestProfileFlow_UpdateWithMissingNameIsRejected(t *testing.T) {
	srv := newTestServer(t)
	client := newHTTPClient(t)

	session, _ := registerAndCompleteSetup(t, client, srv, "missing-name@example.com", "supersecret")

	putResp := doProfileRequest(t, http.MethodPut, srv.URL+"/api/v1/profile", session.AccessToken, map[string]any{
		"firstName": "",
		"lastName":  "Doe",
	})
	if putResp.StatusCode != http.StatusBadRequest {
		t.Fatalf("update with empty first name: status = %d, want %d", putResp.StatusCode, http.StatusBadRequest)
	}
}
