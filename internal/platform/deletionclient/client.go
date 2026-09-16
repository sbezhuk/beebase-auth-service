package deletionclient

import (
	"context"
	"fmt"
	"github.com/google/uuid"
	"net/http"
	"strings"
	"time"
)

type Client struct {
	baseURL, token string
	http           *http.Client
}

func New(baseURL, token string) *Client {
	return &Client{baseURL: strings.TrimRight(baseURL, "/"), token: token, http: &http.Client{Timeout: 25 * time.Second}}
}
func (c *Client) DeleteUserData(ctx context.Context, userID uuid.UUID) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, c.baseURL+"/internal/api/v1/users/"+userID.String(), nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		return nil
	}
	return fmt.Errorf("cleanup returned status %d", resp.StatusCode)
}

func (c *Client) DeleteSessionData(ctx context.Context, userID, sessionID uuid.UUID) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, c.baseURL+"/internal/api/v1/users/"+userID.String()+"/sessions/"+sessionID.String(), nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		return nil
	}
	return fmt.Errorf("session cleanup returned status %d", resp.StatusCode)
}
