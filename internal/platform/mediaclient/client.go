// Package mediaclient implements application/auth.MediaClient against the
// real media-service over HTTP.
package mediaclient

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"time"

	"github.com/google/uuid"

	appauth "github.com/sbezhuk/beebase-auth-service/internal/application/auth"
)

const requestTimeout = 5 * time.Second

// Client implements application/auth.MediaClient against the real
// media-service, forwarding the caller's own access token on every call
// so media-service scopes the check to the same user this service already
// authenticated.
type Client struct {
	baseURL string
	http    *http.Client
}

// New returns a Client that calls media-service at baseURL (e.g.
// "http://media-service:8080").
func New(baseURL string) *Client {
	return &Client{
		baseURL: baseURL,
		http:    &http.Client{Timeout: requestTimeout},
	}
}

// mediaListResponse is the subset of media-service's GET /api/v1/media
// response this client cares about.
type mediaListResponse struct {
	Items []struct {
		ID uuid.UUID `json:"id"`
	} `json:"items"`
}

// VerifyOwnership implements application/auth.MediaClient by calling
// media-service's GET /api/v1/media?ids= - the only remaining source of
// truth for "does this media id exist and belong to me". media-service
// silently omits any id that doesn't exist, was deleted, or belongs to a
// different user, so a response with fewer items than requested means at
// least one id failed that check.
func (c *Client) VerifyOwnership(ctx context.Context, accessToken string, ids []uuid.UUID) error {
	q := url.Values{}
	for _, id := range ids {
		q.Add("ids", id.String())
	}
	u := fmt.Sprintf("%s/api/v1/media?%s", c.baseURL, q.Encode())

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return fmt.Errorf("mediaclient: build request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)

	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("mediaclient: call media-service: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("mediaclient: unexpected status %d from media-service", resp.StatusCode)
	}

	var body mediaListResponse
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return fmt.Errorf("mediaclient: decode response: %w", err)
	}

	if len(body.Items) != len(ids) {
		// At least one requested id wasn't returned: unknown, deleted, or
		// belongs to a different user - indistinguishable to the caller,
		// by the same non-leaking convention user.ErrNotFound follows.
		return appauth.ErrAvatarNotFound
	}

	return nil
}
