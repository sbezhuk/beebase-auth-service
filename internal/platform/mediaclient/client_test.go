package mediaclient_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/uuid"

	appauth "github.com/sbezhuk/beebase-auth-service/internal/application/auth"
	"github.com/sbezhuk/beebase-auth-service/internal/platform/mediaclient"
)

func TestClient_VerifyOwnership_AllOwned(t *testing.T) {
	id1 := uuid.New()
	id2 := uuid.New()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Errorf("method = %q, want GET", r.Method)
		}
		if r.Header.Get("Authorization") != "Bearer good-token" {
			t.Errorf("Authorization header = %q, want forwarded bearer token", r.Header.Get("Authorization"))
		}
		got := r.URL.Query()["ids"]
		if len(got) != 2 || got[0] != id1.String() || got[1] != id2.String() {
			t.Errorf("ids query = %v, want [%s, %s]", got, id1, id2)
		}

		_ = json.NewEncoder(w).Encode(map[string]any{
			"items": []map[string]any{
				{"id": id1.String()},
				{"id": id2.String()},
			},
		})
	}))
	defer srv.Close()

	client := mediaclient.New(srv.URL)
	if err := client.VerifyOwnership(context.Background(), "good-token", []uuid.UUID{id1, id2}); err != nil {
		t.Fatalf("VerifyOwnership: %v", err)
	}
}

func TestClient_VerifyOwnership_FewerItemsMeansNotOwned(t *testing.T) {
	id1 := uuid.New()
	id2 := uuid.New()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"items": []map[string]any{{"id": id1.String()}},
		})
	}))
	defer srv.Close()

	client := mediaclient.New(srv.URL)
	err := client.VerifyOwnership(context.Background(), "good-token", []uuid.UUID{id1, id2})
	if !errors.Is(err, appauth.ErrAvatarNotFound) {
		t.Fatalf("VerifyOwnership with missing item: got %v, want ErrAvatarNotFound", err)
	}
}

func TestClient_DeleteByIDs_Success(t *testing.T) {
	id1 := uuid.New()
	id2 := uuid.New()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodDelete {
			t.Errorf("method = %q, want DELETE", r.Method)
		}
		if r.Header.Get("Authorization") != "Bearer good-token" {
			t.Errorf("Authorization header = %q, want forwarded bearer token", r.Header.Get("Authorization"))
		}
		got := r.URL.Query()["ids"]
		if len(got) != 2 || got[0] != id1.String() || got[1] != id2.String() {
			t.Errorf("ids query = %v, want [%s, %s]", got, id1, id2)
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	client := mediaclient.New(srv.URL)
	if err := client.DeleteByIDs(context.Background(), "good-token", []uuid.UUID{id1, id2}); err != nil {
		t.Fatalf("DeleteByIDs: %v", err)
	}
}

func TestClient_DeleteByIDs_EmptySliceDoesNotCallServer(t *testing.T) {
	called := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	client := mediaclient.New(srv.URL)
	if err := client.DeleteByIDs(context.Background(), "token", nil); err != nil {
		t.Fatalf("DeleteByIDs empty: %v", err)
	}
	if called {
		t.Error("DeleteByIDs with empty slice should return early without calling server")
	}
}

func TestClient_DeleteByIDs_UnexpectedStatusFailsClosed(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	client := mediaclient.New(srv.URL)
	if err := client.DeleteByIDs(context.Background(), "some-token", []uuid.UUID{uuid.New()}); err == nil {
		t.Fatal("DeleteByIDs against a 500: got nil error, want a failure")
	}
}

func TestClient_DeleteAllByUser_Success(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodDelete {
			t.Errorf("method = %q, want DELETE", r.Method)
		}
		if r.URL.Path != "/api/v1/media/mine" {
			t.Errorf("path = %q, want /api/v1/media/mine", r.URL.Path)
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	client := mediaclient.New(srv.URL)
	if err := client.DeleteAllByUser(context.Background(), "token"); err != nil {
		t.Fatalf("DeleteAllByUser: %v", err)
	}
}
