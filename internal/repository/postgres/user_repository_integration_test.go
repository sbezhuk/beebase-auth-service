//go:build integration

package postgres_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/sbezhuk/beebase-auth-service/internal/domain/loginchallenge"
	"github.com/sbezhuk/beebase-auth-service/internal/domain/passwordreset"
	"github.com/sbezhuk/beebase-auth-service/internal/domain/token"
	totpdomain "github.com/sbezhuk/beebase-auth-service/internal/domain/totp"
	"github.com/sbezhuk/beebase-auth-service/internal/domain/user"
	repopostgres "github.com/sbezhuk/beebase-auth-service/internal/repository/postgres"
)

func TestUserRepository_CreateAndGet(t *testing.T) {
	pool := testPool(t)
	ctx := context.Background()

	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin tx: %v", err)
	}
	t.Cleanup(func() { _ = tx.Rollback(ctx) })

	repo := repopostgres.NewUserRepository(tx)

	u := user.New("integration-create@example.com", "hashed-password")
	if err := repo.Create(ctx, u); err != nil {
		t.Fatalf("Create: %v", err)
	}

	byEmail, err := repo.GetByEmail(ctx, u.Email)
	if err != nil {
		t.Fatalf("GetByEmail: %v", err)
	}
	if byEmail.ID != u.ID {
		t.Errorf("GetByEmail returned ID %s, want %s", byEmail.ID, u.ID)
	}

	byID, err := repo.GetByID(ctx, u.ID)
	if err != nil {
		t.Fatalf("GetByID: %v", err)
	}
	if byID.Email != u.Email {
		t.Errorf("GetByID returned email %q, want %q", byID.Email, u.Email)
	}
}

func TestUserRepository_GetByEmail_NotFound(t *testing.T) {
	pool := testPool(t)
	ctx := context.Background()

	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin tx: %v", err)
	}
	t.Cleanup(func() { _ = tx.Rollback(ctx) })

	repo := repopostgres.NewUserRepository(tx)

	_, err = repo.GetByEmail(ctx, "nobody@example.com")
	if !errors.Is(err, user.ErrNotFound) {
		t.Fatalf("GetByEmail for unknown email: got %v, want ErrNotFound", err)
	}
}

func TestUserRepository_GetByID_NotFound(t *testing.T) {
	pool := testPool(t)
	ctx := context.Background()

	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin tx: %v", err)
	}
	t.Cleanup(func() { _ = tx.Rollback(ctx) })

	repo := repopostgres.NewUserRepository(tx)

	_, err = repo.GetByID(ctx, uuid.New())
	if !errors.Is(err, user.ErrNotFound) {
		t.Fatalf("GetByID for unknown id: got %v, want ErrNotFound", err)
	}
}

func TestUserRepository_Update(t *testing.T) {
	pool := testPool(t)
	ctx := context.Background()

	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin tx: %v", err)
	}
	t.Cleanup(func() { _ = tx.Rollback(ctx) })

	repo := repopostgres.NewUserRepository(tx)

	u := user.New("integration-update@example.com", "hashed-password")
	if err := repo.Create(ctx, u); err != nil {
		t.Fatalf("Create: %v", err)
	}

	avatarID := uuid.New()
	u.UpdateProfile("Jane", "Doe", &avatarID)
	if err := repo.Update(ctx, u); err != nil {
		t.Fatalf("Update: %v", err)
	}

	got, err := repo.GetByID(ctx, u.ID)
	if err != nil {
		t.Fatalf("GetByID: %v", err)
	}
	if got.FirstName != "Jane" || got.LastName != "Doe" {
		t.Errorf("name = %q %q, want Jane Doe", got.FirstName, got.LastName)
	}
	if got.AvatarMediaID == nil || *got.AvatarMediaID != avatarID {
		t.Errorf("AvatarMediaID = %v, want %v", got.AvatarMediaID, avatarID)
	}

	// Removing the avatar (nil) must persist as NULL, not be left alone.
	u.UpdateProfile("Jane", "Doe", nil)
	if err := repo.Update(ctx, u); err != nil {
		t.Fatalf("Update (remove avatar): %v", err)
	}
	got, err = repo.GetByID(ctx, u.ID)
	if err != nil {
		t.Fatalf("GetByID after removing avatar: %v", err)
	}
	if got.AvatarMediaID != nil {
		t.Errorf("AvatarMediaID = %v, want nil after removal", got.AvatarMediaID)
	}
}

func TestUserRepository_Update_NotFound(t *testing.T) {
	pool := testPool(t)
	ctx := context.Background()

	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin tx: %v", err)
	}
	t.Cleanup(func() { _ = tx.Rollback(ctx) })

	repo := repopostgres.NewUserRepository(tx)

	u := user.New("integration-update-missing@example.com", "hashed-password")
	// Deliberately never created.
	err = repo.Update(ctx, u)
	if !errors.Is(err, user.ErrNotFound) {
		t.Fatalf("Update for unknown user: got %v, want ErrNotFound", err)
	}
}

// TestUserRepository_DuplicateEmail verifies the repository translates a
// unique-constraint violation into the domain's ErrEmailTaken. The second
// insert attempt runs inside a SAVEPOINT: a failed statement aborts the
// enclosing transaction in PostgreSQL, so without the savepoint the outer
// rollback-only-cleanup pattern used by every other test here couldn't
// recover to check the returned error.
func TestUserRepository_DuplicateEmail(t *testing.T) {
	pool := testPool(t)
	ctx := context.Background()

	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin tx: %v", err)
	}
	t.Cleanup(func() { _ = tx.Rollback(ctx) })

	email := "integration-dup@example.com"
	repo := repopostgres.NewUserRepository(tx)

	if err := repo.Create(ctx, user.New(email, "hash-one")); err != nil {
		t.Fatalf("first Create: %v", err)
	}

	savepoint, err := tx.Begin(ctx)
	if err != nil {
		t.Fatalf("begin savepoint: %v", err)
	}

	err = repopostgres.NewUserRepository(savepoint).Create(ctx, user.New(email, "hash-two"))
	_ = savepoint.Rollback(ctx)

	if !errors.Is(err, user.ErrEmailTaken) {
		t.Fatalf("second Create with duplicate email: got %v, want ErrEmailTaken", err)
	}
}

func TestUserRepository_Delete(t *testing.T) {
	pool := testPool(t)
	ctx := context.Background()

	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin tx: %v", err)
	}
	t.Cleanup(func() { _ = tx.Rollback(ctx) })

	repo := repopostgres.NewUserRepository(tx)
	u := seedUser(t, ctx, tx, "integration-delete@example.com")

	if err := repo.Delete(ctx, u.ID); err != nil {
		t.Fatalf("Delete: %v", err)
	}

	if _, err := repo.GetByID(ctx, u.ID); !errors.Is(err, user.ErrNotFound) {
		t.Fatalf("GetByID after Delete: got %v, want ErrNotFound", err)
	}
}

func TestUserRepository_Delete_NotFound(t *testing.T) {
	pool := testPool(t)
	ctx := context.Background()

	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin tx: %v", err)
	}
	t.Cleanup(func() { _ = tx.Rollback(ctx) })

	repo := repopostgres.NewUserRepository(tx)

	if err := repo.Delete(ctx, uuid.New()); !errors.Is(err, user.ErrNotFound) {
		t.Fatalf("Delete for unknown id: got %v, want ErrNotFound", err)
	}
}

// TestUserRepository_Delete_CascadesRelatedTables proves the schema's own
// ON DELETE CASCADE foreign keys do the rest of account deletion's local
// cleanup: deleting the user row alone must be enough to remove every
// refresh token, TOTP credential, login challenge, and password-reset flow
// that referenced it - application/auth.Service.DeleteAccount relies on
// this rather than deleting each of those tables itself.
func TestUserRepository_Delete_CascadesRelatedTables(t *testing.T) {
	pool := testPool(t)
	ctx := context.Background()

	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin tx: %v", err)
	}
	t.Cleanup(func() { _ = tx.Rollback(ctx) })

	u := seedUser(t, ctx, tx, "integration-delete-cascade@example.com")

	refreshTokenRepo := repopostgres.NewRefreshTokenRepository(tx)
	rt := token.New(u.ID, "refresh-token-hash", time.Hour)
	if err := refreshTokenRepo.Create(ctx, rt); err != nil {
		t.Fatalf("seed refresh token: %v", err)
	}

	credentialRepo := repopostgres.NewTwoFactorCredentialRepository(tx)
	cred := totpdomain.New(u.ID, []byte("encrypted-secret"), "setup-token-hash", time.Hour)
	if err := credentialRepo.Create(ctx, cred); err != nil {
		t.Fatalf("seed totp credential: %v", err)
	}

	loginChallengeRepo := repopostgres.NewLoginChallengeRepository(tx)
	challenge := loginchallenge.New(u.ID, "challenge-token-hash", time.Hour)
	if err := loginChallengeRepo.Create(ctx, challenge); err != nil {
		t.Fatalf("seed login challenge: %v", err)
	}

	passwordResetFlowRepo := repopostgres.NewPasswordResetFlowRepository(tx)
	flow := passwordreset.New(&u.ID, "flow-token-hash", time.Hour)
	if err := passwordResetFlowRepo.Create(ctx, flow); err != nil {
		t.Fatalf("seed password reset flow: %v", err)
	}

	if err := repopostgres.NewUserRepository(tx).Delete(ctx, u.ID); err != nil {
		t.Fatalf("Delete: %v", err)
	}

	if _, err := refreshTokenRepo.GetByHash(ctx, "refresh-token-hash"); !errors.Is(err, token.ErrNotFound) {
		t.Errorf("refresh token after user Delete: got %v, want ErrNotFound (cascade)", err)
	}
	if _, err := credentialRepo.GetByUserID(ctx, u.ID); !errors.Is(err, totpdomain.ErrNotFound) {
		t.Errorf("totp credential after user Delete: got %v, want ErrNotFound (cascade)", err)
	}
	if _, err := loginChallengeRepo.GetByHash(ctx, "challenge-token-hash"); !errors.Is(err, loginchallenge.ErrNotFound) {
		t.Errorf("login challenge after user Delete: got %v, want ErrNotFound (cascade)", err)
	}
	if _, err := passwordResetFlowRepo.GetByFlowTokenHash(ctx, "flow-token-hash"); !errors.Is(err, passwordreset.ErrNotFound) {
		t.Errorf("password reset flow after user Delete: got %v, want ErrNotFound (cascade)", err)
	}
}
