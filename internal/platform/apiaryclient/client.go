// Package apiaryclient implements application/auth.ApiaryCascadeDeleter
// against the real apiary-service over HTTP.
package apiaryclient

import (
	"context"
	"fmt"
	"net/http"
	"time"
)

const requestTimeout = 5 * time.Second

// Client cascades a delete for every apiary the caller owns by calling
// apiary-service's DELETE /api/v1/apiaries, forwarding the caller's own
// access token so apiary-service (and, transitively, hive-service,
// inspection-service, and media-service) scope the delete to the same user
// this service already authenticated.
type Client struct {
	baseURL string
	http    *http.Client
}

// New returns a Client that calls apiary-service at baseURL (e.g.
// "http://apiary-service:8080").
func New(baseURL string) *Client {
	return &Client{
		baseURL: baseURL,
		http:    &http.Client{Timeout: requestTimeout},
	}
}

// DeleteAllMine implements application/auth.ApiaryCascadeDeleter.
func (c *Client) DeleteAllMine(ctx context.Context, accessToken string) error {
	u := c.baseURL + "/api/v1/apiaries"

	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, u, nil)
	if err != nil {
		return fmt.Errorf("apiaryclient: build request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)

	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("apiaryclient: call apiary-service: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	switch resp.StatusCode {
	case http.StatusNoContent, http.StatusOK:
		return nil
	default:
		return fmt.Errorf("apiaryclient: unexpected status %d from apiary-service", resp.StatusCode)
	}
}
