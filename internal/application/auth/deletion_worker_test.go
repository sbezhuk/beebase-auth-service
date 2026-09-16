package auth

import (
	"context"
	"errors"
	"github.com/google/uuid"
	"log/slog"
	"testing"
)

type testDeletionStore struct {
	job       *DeletionJob
	completed []string
	retries   int
	done      bool
}

func (s *testDeletionStore) ClaimDeletion(context.Context) (*DeletionJob, error) {
	if s.job == nil || s.done {
		return nil, nil
	}
	return s.job, nil
}
func (s *testDeletionStore) CompleteDeletionStep(_ context.Context, _ uuid.UUID, name string) error {
	s.completed = append(s.completed, name)
	for i := range s.job.Steps {
		if s.job.Steps[i].Service == name {
			s.job.Steps[i].Status = "completed"
		}
	}
	return nil
}
func (s *testDeletionStore) RetryDeletionStep(context.Context, uuid.UUID, string, int, string) error {
	s.retries++
	return nil
}
func (s *testDeletionStore) CompleteDeletionJob(context.Context, uuid.UUID) error {
	s.done = true
	return nil
}

type testCleanup struct {
	calls int
	fail  bool
}

func (c *testCleanup) DeleteUserData(context.Context, uuid.UUID) error {
	c.calls++
	if c.fail {
		return errors.New("temporary")
	}
	return nil
}

type testUserDelete struct{ calls int }

func (u *testUserDelete) Delete(context.Context, uuid.UUID) error { u.calls++; return nil }

func TestDeletionWorkerRetriesFailureAndResumes(t *testing.T) {
	store := &testDeletionStore{job: &DeletionJob{ID: uuid.New(), UserID: uuid.New(), Steps: []DeletionStep{{Service: "apiary"}, {Service: "harvest"}}}}
	apiary := &testCleanup{}
	harvest := &testCleanup{fail: true}
	users := &testUserDelete{}
	w := NewDeletionWorker(store, users, map[string]AccountCleanupClient{"apiary": apiary, "harvest": harvest}, slog.Default())
	if err := w.RunOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	if apiary.calls != 1 || harvest.calls != 1 || store.retries != 1 || users.calls != 0 {
		t.Fatalf("first run calls apiary=%d harvest=%d retries=%d users=%d", apiary.calls, harvest.calls, store.retries, users.calls)
	}
	harvest.fail = false
	if err := w.RunOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	if users.calls != 1 || !store.done {
		t.Fatalf("recovery did not finalize: users=%d done=%v", users.calls, store.done)
	}
}
