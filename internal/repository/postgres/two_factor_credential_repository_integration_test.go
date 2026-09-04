//go:build integration

package postgres_test

import (
	"context"
	"crypto/rand"
	"errors"
	"testing"
	"time"

	totpdomain "github.com/sbezhuk/beebase-auth-service/internal/domain/totp"
	"github.com/sbezhuk/beebase-auth-service/internal/platform/totpsecret"
	repopostgres "github.com/sbezhuk/beebase-auth-service/internal/repository/postgres"
)

func TestTwoFactorCredentialRepository_CreateAndGetByUserID_EncryptedSecretRoundTrips(t *testing.T) {
	pool := testPool(t)
	ctx := context.Background()

	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin tx: %v", err)
	}
	t.Cleanup(func() { _ = tx.Rollback(ctx) })

	u := seedUser(t, ctx, tx, "totp-create@example.com")
	repo := repopostgres.NewTwoFactorCredentialRepository(tx)

	key := make([]byte, totpsecret.KeySize)
	if _, err := rand.Read(key); err != nil {
		t.Fatalf("generate cipher key: %v", err)
	}
	cipher, err := totpsecret.NewCipher(key)
	if err != nil {
		t.Fatalf("new cipher: %v", err)
	}

	plainSecret := "JBSWY3DPEHPK3PXP"
	encrypted, err := cipher.Encrypt([]byte(plainSecret))
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}

	c := totpdomain.New(u.ID, encrypted, "hash-of-setup-token", time.Hour)
	if err := repo.Create(ctx, c); err != nil {
		t.Fatalf("Create: %v", err)
	}

	got, err := repo.GetByUserID(ctx, u.ID)
	if err != nil {
		t.Fatalf("GetByUserID: %v", err)
	}
	if got.IsEnabled() {
		t.Error("freshly created credential should not be enabled")
	}

	decrypted, err := cipher.Decrypt(got.SecretEncrypted)
	if err != nil {
		t.Fatalf("decrypt round-tripped secret: %v", err)
	}
	if string(decrypted) != plainSecret {
		t.Errorf("decrypted secret = %q, want %q", decrypted, plainSecret)
	}
}

func TestTwoFactorCredentialRepository_GetByUserID_NotFound(t *testing.T) {
	pool := testPool(t)
	ctx := context.Background()

	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin tx: %v", err)
	}
	t.Cleanup(func() { _ = tx.Rollback(ctx) })

	u := seedUser(t, ctx, tx, "totp-notfound@example.com")

	_, err = repopostgres.NewTwoFactorCredentialRepository(tx).GetByUserID(ctx, u.ID)
	if !errors.Is(err, totpdomain.ErrNotFound) {
		t.Fatalf("GetByUserID for user with no credential: got %v, want ErrNotFound", err)
	}
}

func TestTwoFactorCredentialRepository_GetBySetupTokenHash(t *testing.T) {
	pool := testPool(t)
	ctx := context.Background()

	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin tx: %v", err)
	}
	t.Cleanup(func() { _ = tx.Rollback(ctx) })

	u := seedUser(t, ctx, tx, "totp-setuphash@example.com")
	repo := repopostgres.NewTwoFactorCredentialRepository(tx)

	c := totpdomain.New(u.ID, []byte("ciphertext"), "hash-of-setup-token", time.Hour)
	if err := repo.Create(ctx, c); err != nil {
		t.Fatalf("Create: %v", err)
	}

	got, err := repo.GetBySetupTokenHash(ctx, "hash-of-setup-token")
	if err != nil {
		t.Fatalf("GetBySetupTokenHash: %v", err)
	}
	if got.UserID != u.ID {
		t.Errorf("GetBySetupTokenHash returned UserID %v, want %v", got.UserID, u.ID)
	}

	if _, err := repo.GetBySetupTokenHash(ctx, "does-not-exist"); !errors.Is(err, totpdomain.ErrNotFound) {
		t.Fatalf("GetBySetupTokenHash for unknown hash: got %v, want ErrNotFound", err)
	}
}

func TestTwoFactorCredentialRepository_Update_EnablesAndClearsSetupToken(t *testing.T) {
	pool := testPool(t)
	ctx := context.Background()

	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin tx: %v", err)
	}
	t.Cleanup(func() { _ = tx.Rollback(ctx) })

	u := seedUser(t, ctx, tx, "totp-update@example.com")
	repo := repopostgres.NewTwoFactorCredentialRepository(tx)

	c := totpdomain.New(u.ID, []byte("ciphertext"), "hash-of-setup-token", time.Hour)
	if err := repo.Create(ctx, c); err != nil {
		t.Fatalf("Create: %v", err)
	}

	c.Enable()
	if err := repo.Update(ctx, c); err != nil {
		t.Fatalf("Update: %v", err)
	}

	got, err := repo.GetByUserID(ctx, u.ID)
	if err != nil {
		t.Fatalf("GetByUserID: %v", err)
	}
	if !got.IsEnabled() {
		t.Error("credential should be enabled after Update")
	}
	if got.SetupTokenHash != nil {
		t.Error("setup token hash should be cleared once enabled")
	}

	// The consumed setup token must no longer resolve.
	if _, err := repo.GetBySetupTokenHash(ctx, "hash-of-setup-token"); !errors.Is(err, totpdomain.ErrNotFound) {
		t.Fatalf("GetBySetupTokenHash after enabling: got %v, want ErrNotFound", err)
	}
}

func TestTwoFactorCredentialRepository_Update_NotFound(t *testing.T) {
	pool := testPool(t)
	ctx := context.Background()

	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin tx: %v", err)
	}
	t.Cleanup(func() { _ = tx.Rollback(ctx) })

	c := totpdomain.New(seedUser(t, ctx, tx, "totp-update-notfound@example.com").ID, []byte("ciphertext"), "some-hash", time.Hour)
	// Never created.

	err = repopostgres.NewTwoFactorCredentialRepository(tx).Update(ctx, c)
	if !errors.Is(err, totpdomain.ErrNotFound) {
		t.Fatalf("Update of never-created credential: got %v, want ErrNotFound", err)
	}
}
