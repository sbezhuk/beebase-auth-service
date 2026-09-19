package auth_test

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/sbezhuk/beebase-auth-service/internal/domain/loginchallenge"
	"github.com/sbezhuk/beebase-auth-service/internal/domain/passwordreset"
	totpdomain "github.com/sbezhuk/beebase-auth-service/internal/domain/totp"
)

// fakeCredentialRepo is an in-memory stand-in for domain/totp.Repository,
// mirroring fakeUserRepo's shape (mutex-guarded maps, defensive copies
// in/out to catch aliasing bugs).
type fakeCredentialRepo struct {
	mu          sync.Mutex
	byUserID    map[uuid.UUID]*totpdomain.Credential
	bySetupHash map[string]uuid.UUID
}

func newFakeCredentialRepo() *fakeCredentialRepo {
	return &fakeCredentialRepo{
		byUserID:    map[uuid.UUID]*totpdomain.Credential{},
		bySetupHash: map[string]uuid.UUID{},
	}
}

func (f *fakeCredentialRepo) Create(_ context.Context, c *totpdomain.Credential) error {
	f.mu.Lock()
	defer f.mu.Unlock()

	cp := *c
	f.byUserID[c.UserID] = &cp
	if c.SetupTokenHash != nil {
		f.bySetupHash[*c.SetupTokenHash] = c.UserID
	}
	return nil
}

func (f *fakeCredentialRepo) GetByUserID(_ context.Context, userID uuid.UUID) (*totpdomain.Credential, error) {
	f.mu.Lock()
	defer f.mu.Unlock()

	c, ok := f.byUserID[userID]
	if !ok {
		return nil, totpdomain.ErrNotFound
	}
	cp := *c
	return &cp, nil
}

func (f *fakeCredentialRepo) GetBySetupTokenHash(_ context.Context, hash string) (*totpdomain.Credential, error) {
	f.mu.Lock()
	defer f.mu.Unlock()

	userID, ok := f.bySetupHash[hash]
	if !ok {
		return nil, totpdomain.ErrNotFound
	}
	cp := *f.byUserID[userID]
	return &cp, nil
}

func (f *fakeCredentialRepo) Update(_ context.Context, c *totpdomain.Credential) error {
	f.mu.Lock()
	defer f.mu.Unlock()

	existing, ok := f.byUserID[c.UserID]
	if !ok {
		return totpdomain.ErrNotFound
	}
	if existing.SetupTokenHash != nil {
		delete(f.bySetupHash, *existing.SetupTokenHash)
	}

	cp := *c
	f.byUserID[c.UserID] = &cp
	if c.SetupTokenHash != nil {
		f.bySetupHash[*c.SetupTokenHash] = c.UserID
	}
	return nil
}

// fakeLoginChallengeRepo is an in-memory stand-in for
// domain/loginchallenge.Repository.
type fakeLoginChallengeRepo struct {
	mu     sync.Mutex
	byID   map[uuid.UUID]*loginchallenge.LoginChallenge
	byHash map[string]uuid.UUID
}

func newFakeLoginChallengeRepo() *fakeLoginChallengeRepo {
	return &fakeLoginChallengeRepo{
		byID:   map[uuid.UUID]*loginchallenge.LoginChallenge{},
		byHash: map[string]uuid.UUID{},
	}
}

func (f *fakeLoginChallengeRepo) Create(_ context.Context, c *loginchallenge.LoginChallenge) error {
	f.mu.Lock()
	defer f.mu.Unlock()

	cp := *c
	f.byID[c.ID] = &cp
	f.byHash[c.TokenHash] = c.ID
	return nil
}

func (f *fakeLoginChallengeRepo) GetByHash(_ context.Context, hash string) (*loginchallenge.LoginChallenge, error) {
	f.mu.Lock()
	defer f.mu.Unlock()

	id, ok := f.byHash[hash]
	if !ok {
		return nil, loginchallenge.ErrNotFound
	}
	cp := *f.byID[id]
	return &cp, nil
}

func (f *fakeLoginChallengeRepo) Consume(_ context.Context, id uuid.UUID) error {
	f.mu.Lock()
	defer f.mu.Unlock()

	c, ok := f.byID[id]
	if !ok {
		return nil
	}
	now := time.Now().UTC()
	c.ConsumedAt = &now
	return nil
}

// fakePasswordResetFlowRepo is an in-memory stand-in for
// domain/passwordreset.Repository.
type fakePasswordResetFlowRepo struct {
	mu          sync.Mutex
	byID        map[uuid.UUID]*passwordreset.PasswordResetFlow
	byFlowHash  map[string]uuid.UUID
	byResetHash map[string]uuid.UUID
}

func newFakePasswordResetFlowRepo() *fakePasswordResetFlowRepo {
	return &fakePasswordResetFlowRepo{
		byID:        map[uuid.UUID]*passwordreset.PasswordResetFlow{},
		byFlowHash:  map[string]uuid.UUID{},
		byResetHash: map[string]uuid.UUID{},
	}
}

func (f *fakePasswordResetFlowRepo) Create(_ context.Context, flow *passwordreset.PasswordResetFlow) error {
	f.mu.Lock()
	defer f.mu.Unlock()

	cp := *flow
	f.byID[flow.ID] = &cp
	f.byFlowHash[flow.FlowTokenHash] = flow.ID
	if flow.ResetTokenHash != nil {
		f.byResetHash[*flow.ResetTokenHash] = flow.ID
	}
	return nil
}

func (f *fakePasswordResetFlowRepo) GetByFlowTokenHash(_ context.Context, hash string) (*passwordreset.PasswordResetFlow, error) {
	f.mu.Lock()
	defer f.mu.Unlock()

	id, ok := f.byFlowHash[hash]
	if !ok {
		return nil, passwordreset.ErrNotFound
	}
	cp := *f.byID[id]
	return &cp, nil
}

func (f *fakePasswordResetFlowRepo) GetByResetTokenHash(_ context.Context, hash string) (*passwordreset.PasswordResetFlow, error) {
	f.mu.Lock()
	defer f.mu.Unlock()

	id, ok := f.byResetHash[hash]
	if !ok {
		return nil, passwordreset.ErrNotFound
	}
	cp := *f.byID[id]
	return &cp, nil
}

func (f *fakePasswordResetFlowRepo) Update(_ context.Context, flow *passwordreset.PasswordResetFlow) error {
	f.mu.Lock()
	defer f.mu.Unlock()

	existing, ok := f.byID[flow.ID]
	if !ok {
		return passwordreset.ErrNotFound
	}
	if existing.ResetTokenHash != nil {
		delete(f.byResetHash, *existing.ResetTokenHash)
	}

	cp := *flow
	f.byID[flow.ID] = &cp
	if flow.ResetTokenHash != nil {
		f.byResetHash[*flow.ResetTokenHash] = flow.ID
	}
	return nil
}

// sessionCleanupCall records one DeleteSessionData invocation observed by
// fakeSessionCleaner.
type sessionCleanupCall struct {
	userID, previousSessionID uuid.UUID
}

// fakeSessionCleaner is an in-memory stand-in for the notification-service
// session-cleanup dependency (mirrors cmd/server/main.go's
// sessionCleanupRequester, which satisfies both appauth.DeletionRequester
// and appauth.SessionCleanupRequester with the same concrete type).
//
// issueSession's cleanup call runs in its own goroutine, detached from the
// request that triggered it (see cleanupSessionDevices) - so a
// test can't just call DeleteSessionData and inline-assert what happened,
// the way it could with every other synchronous fake in this package. calls
// is a buffered channel a test receives from (via waitForCall) to
// deterministically observe that the goroutine ran, instead of sleeping
// and hoping.
type fakeSessionCleaner struct {
	err   error
	calls chan sessionCleanupCall
}

// newFakeSessionCleaner returns a fakeSessionCleaner whose DeleteSessionData
// always returns err (nil for "cleanup succeeds").
func newFakeSessionCleaner(err error) *fakeSessionCleaner {
	return &fakeSessionCleaner{err: err, calls: make(chan sessionCleanupCall, 8)}
}

func (f *fakeSessionCleaner) RequestDeletion(_ context.Context, _ uuid.UUID) error {
	return nil
}

func (f *fakeSessionCleaner) DeleteSessionData(_ context.Context, userID, previousSessionID uuid.UUID) error {
	f.calls <- sessionCleanupCall{userID: userID, previousSessionID: previousSessionID}
	return f.err
}

// waitForCall blocks until DeleteSessionData has been invoked and returns
// that call, failing t if none arrives within the timeout. Used to
// deterministically synchronize with issueSession's detached cleanup
// goroutine without a fixed sleep.
func (f *fakeSessionCleaner) waitForCall(t *testing.T) sessionCleanupCall {
	t.Helper()
	select {
	case call := <-f.calls:
		return call
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for DeleteSessionData to be called")
		return sessionCleanupCall{}
	}
}

// assertNeverCalled fails t if DeleteSessionData is invoked within a short
// grace period - used to confirm the hadPrevious=false path skips cleanup
// entirely, without making the common case pay for a long sleep.
func (f *fakeSessionCleaner) assertNeverCalled(t *testing.T) {
	t.Helper()
	select {
	case call := <-f.calls:
		t.Fatalf("DeleteSessionData was called unexpectedly: %+v", call)
	case <-time.After(100 * time.Millisecond):
	}
}

// fakeDeletionRequester is an in-memory stand-in for the durable
// account-deletion dependency (appauth.DeletionRequester), separate from
// fakeSessionCleaner because DeleteAccount's request-time path only ever
// calls RequestDeletion synchronously - the per-service cleanup steps
// (including notification) are the durable DeletionWorker's job, already
// covered by TestDeletionWorkerRetriesFailureAndResumes in
// deletion_worker_test.go. This fake exists purely to prove DeleteAccount
// itself takes the durable-job path (matching cmd/server/main.go's
// production wiring, which every pre-existing DeleteAccount test bypasses
// by never passing a DeletionRequester at all - see
// newTestServiceForDelete) and that it does so regardless of any
// downstream service's health, since nothing downstream is ever called
// synchronously from here.
type fakeDeletionRequester struct {
	mu       sync.Mutex
	requests []uuid.UUID
	err      error
}

func newFakeDeletionRequester(err error) *fakeDeletionRequester {
	return &fakeDeletionRequester{err: err}
}

func (f *fakeDeletionRequester) RequestDeletion(_ context.Context, userID uuid.UUID) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.requests = append(f.requests, userID)
	return f.err
}

func (f *fakeDeletionRequester) calledWith(userID uuid.UUID) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, id := range f.requests {
		if id == userID {
			return true
		}
	}
	return false
}
