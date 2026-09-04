package auth_test

import (
	"context"
	"sync"
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
