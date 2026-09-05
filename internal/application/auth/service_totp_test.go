package auth_test

import (
	"context"
	"errors"
	"testing"

	"github.com/google/uuid"

	appauth "github.com/sbezhuk/beebase-auth-service/internal/application/auth"
	"github.com/sbezhuk/beebase-auth-service/internal/domain/user"
)

// --- SetupVerifyOTP ---

func TestSetupVerifyOTP_WrongCode(t *testing.T) {
	svc, _, _ := newTestService()
	setup, err := svc.Register(context.Background(), appauth.RegisterInput{Email: "bee@example.com", Password: "supersecret"})
	if err != nil {
		t.Fatalf("Register: %v", err)
	}

	if _, err := svc.SetupVerifyOTP(context.Background(), setup.SetupToken, "000000"); !errors.Is(err, appauth.ErrOTPInvalid) {
		t.Fatalf("SetupVerifyOTP wrong code: got %v, want ErrOTPInvalid", err)
	}
}

func TestSetupVerifyOTP_UnknownToken(t *testing.T) {
	svc, _, _ := newTestService()

	if _, err := svc.SetupVerifyOTP(context.Background(), "not-a-real-token", "123456"); !errors.Is(err, appauth.ErrSetupTokenInvalid) {
		t.Fatalf("SetupVerifyOTP unknown token: got %v, want ErrSetupTokenInvalid", err)
	}
}

func TestSetupVerifyOTP_SetupTokenNotReusableAfterEnabling(t *testing.T) {
	svc, _, _ := newTestService()
	setup, err := svc.Register(context.Background(), appauth.RegisterInput{Email: "bee@example.com", Password: "supersecret"})
	if err != nil {
		t.Fatalf("Register: %v", err)
	}
	code := genCode(t, setup.Secret)

	if _, err := svc.SetupVerifyOTP(context.Background(), setup.SetupToken, code); err != nil {
		t.Fatalf("first SetupVerifyOTP: %v", err)
	}

	if _, err := svc.SetupVerifyOTP(context.Background(), setup.SetupToken, code); !errors.Is(err, appauth.ErrSetupTokenInvalid) {
		t.Fatalf("replayed SetupVerifyOTP: got %v, want ErrSetupTokenInvalid", err)
	}
}

// --- LoginVerifyOTP ---

func TestLoginVerifyOTP_Success(t *testing.T) {
	svc, _, _ := newTestService()
	setup, err := svc.Register(context.Background(), appauth.RegisterInput{Email: "bee@example.com", Password: "supersecret"})
	if err != nil {
		t.Fatalf("Register: %v", err)
	}
	if _, err := svc.SetupVerifyOTP(context.Background(), setup.SetupToken, genCode(t, setup.Secret)); err != nil {
		t.Fatalf("SetupVerifyOTP: %v", err)
	}

	login, err := svc.Login(context.Background(), appauth.LoginInput{Email: "bee@example.com", Password: "supersecret"})
	if err != nil {
		t.Fatalf("Login: %v", err)
	}

	session, err := svc.LoginVerifyOTP(context.Background(), login.ChallengeToken, genNextCode(t, setup.Secret))
	if err != nil {
		t.Fatalf("LoginVerifyOTP: %v", err)
	}
	if session.AccessToken == "" || session.RefreshToken == "" {
		t.Error("LoginVerifyOTP did not issue a full session")
	}
}

func TestLoginVerifyOTP_WrongCode_NoSessionIssued(t *testing.T) {
	svc, _, _ := newTestService()
	mustRegister(t, svc, "bee@example.com", "supersecret")

	login, err := svc.Login(context.Background(), appauth.LoginInput{Email: "bee@example.com", Password: "supersecret"})
	if err != nil {
		t.Fatalf("Login: %v", err)
	}

	if _, err := svc.LoginVerifyOTP(context.Background(), login.ChallengeToken, "000000"); !errors.Is(err, appauth.ErrOTPInvalid) {
		t.Fatalf("LoginVerifyOTP wrong code: got %v, want ErrOTPInvalid", err)
	}
}

func TestLoginVerifyOTP_ChallengeNotReplayable(t *testing.T) {
	svc, _, _ := newTestService()
	setup, err := svc.Register(context.Background(), appauth.RegisterInput{Email: "bee@example.com", Password: "supersecret"})
	if err != nil {
		t.Fatalf("Register: %v", err)
	}
	if _, err := svc.SetupVerifyOTP(context.Background(), setup.SetupToken, genCode(t, setup.Secret)); err != nil {
		t.Fatalf("SetupVerifyOTP: %v", err)
	}

	login, err := svc.Login(context.Background(), appauth.LoginInput{Email: "bee@example.com", Password: "supersecret"})
	if err != nil {
		t.Fatalf("Login: %v", err)
	}

	code := genNextCode(t, setup.Secret)
	if _, err := svc.LoginVerifyOTP(context.Background(), login.ChallengeToken, code); err != nil {
		t.Fatalf("first LoginVerifyOTP: %v", err)
	}
	if _, err := svc.LoginVerifyOTP(context.Background(), login.ChallengeToken, code); !errors.Is(err, appauth.ErrChallengeInvalid) {
		t.Fatalf("replayed LoginVerifyOTP: got %v, want ErrChallengeInvalid", err)
	}
}

// TestLoginVerifyOTP_ReplayedCodeRejectedAcrossChallenges is the regression
// test for BEEB-41: a TOTP code, once accepted, must never authenticate
// again - even against a brand new login challenge - since it may have
// been captured by an attacker (shoulder-surfing, network interception)
// rather than only ever seen by the legitimate user.
func TestLoginVerifyOTP_ReplayedCodeRejectedAcrossChallenges(t *testing.T) {
	svc, _, _ := newTestService()
	setup, err := svc.Register(context.Background(), appauth.RegisterInput{Email: "bee@example.com", Password: "supersecret"})
	if err != nil {
		t.Fatalf("Register: %v", err)
	}
	if _, err := svc.SetupVerifyOTP(context.Background(), setup.SetupToken, genCode(t, setup.Secret)); err != nil {
		t.Fatalf("SetupVerifyOTP: %v", err)
	}

	login1, err := svc.Login(context.Background(), appauth.LoginInput{Email: "bee@example.com", Password: "supersecret"})
	if err != nil {
		t.Fatalf("Login #1: %v", err)
	}
	code := genNextCode(t, setup.Secret)
	if _, err := svc.LoginVerifyOTP(context.Background(), login1.ChallengeToken, code); err != nil {
		t.Fatalf("first LoginVerifyOTP: %v", err)
	}

	login2, err := svc.Login(context.Background(), appauth.LoginInput{Email: "bee@example.com", Password: "supersecret"})
	if err != nil {
		t.Fatalf("Login #2: %v", err)
	}
	if _, err := svc.LoginVerifyOTP(context.Background(), login2.ChallengeToken, code); !errors.Is(err, appauth.ErrOTPInvalid) {
		t.Fatalf("replaying the same code against a fresh challenge: got %v, want ErrOTPInvalid", err)
	}
}

func TestLoginVerifyOTP_UnknownChallenge(t *testing.T) {
	svc, _, _ := newTestService()

	if _, err := svc.LoginVerifyOTP(context.Background(), "not-a-real-challenge", "123456"); !errors.Is(err, appauth.ErrChallengeInvalid) {
		t.Fatalf("LoginVerifyOTP unknown challenge: got %v, want ErrChallengeInvalid", err)
	}
}

// --- Account-level OTP lockout ---

func TestOTPLockout_AfterMaxAttempts_RejectsSubsequentValidCode(t *testing.T) {
	svc, _, _ := newTestService()
	setup, err := svc.Register(context.Background(), appauth.RegisterInput{Email: "bee@example.com", Password: "supersecret"})
	if err != nil {
		t.Fatalf("Register: %v", err)
	}
	if _, err := svc.SetupVerifyOTP(context.Background(), setup.SetupToken, genCode(t, setup.Secret)); err != nil {
		t.Fatalf("SetupVerifyOTP: %v", err)
	}

	// newTestSecurityConfig sets OTPMaxAttempts to 5.
	for i := 0; i < 5; i++ {
		login, err := svc.Login(context.Background(), appauth.LoginInput{Email: "bee@example.com", Password: "supersecret"})
		if err != nil {
			t.Fatalf("Login #%d: %v", i, err)
		}
		if _, err := svc.LoginVerifyOTP(context.Background(), login.ChallengeToken, "000000"); err == nil {
			t.Fatalf("attempt #%d: wrong code unexpectedly succeeded", i)
		}
	}

	login, err := svc.Login(context.Background(), appauth.LoginInput{Email: "bee@example.com", Password: "supersecret"})
	if err != nil {
		t.Fatalf("Login after exhausting attempts: %v", err)
	}
	if _, err := svc.LoginVerifyOTP(context.Background(), login.ChallengeToken, genNextCode(t, setup.Secret)); !errors.Is(err, appauth.ErrOTPLocked) {
		t.Fatalf("LoginVerifyOTP with valid code while locked: got %v, want ErrOTPLocked", err)
	}
}

// --- ChangePassword ---

func TestChangePassword_Success_RevokesOldSessions(t *testing.T) {
	svc, _, _ := newTestService()
	setup, err := svc.Register(context.Background(), appauth.RegisterInput{Email: "bee@example.com", Password: "supersecret"})
	if err != nil {
		t.Fatalf("Register: %v", err)
	}
	session, err := svc.SetupVerifyOTP(context.Background(), setup.SetupToken, genCode(t, setup.Secret))
	if err != nil {
		t.Fatalf("SetupVerifyOTP: %v", err)
	}

	if err := svc.ChangePassword(context.Background(), session.UserID, appauth.ChangePasswordInput{
		CurrentPassword: "supersecret",
		NewPassword:     "brandnewpassword",
		OTP:             genNextCode(t, setup.Secret),
	}); err != nil {
		t.Fatalf("ChangePassword: %v", err)
	}

	if _, err := svc.Refresh(context.Background(), session.RefreshToken); !errors.Is(err, appauth.ErrInvalidRefreshToken) {
		t.Fatalf("Refresh with pre-change token: got %v, want ErrInvalidRefreshToken", err)
	}

	if _, err := svc.Login(context.Background(), appauth.LoginInput{Email: "bee@example.com", Password: "brandnewpassword"}); err != nil {
		t.Fatalf("Login with new password: %v", err)
	}
}

func TestChangePassword_WrongCurrentPassword_PasswordUnchanged(t *testing.T) {
	svc, _, _ := newTestService()
	setup, err := svc.Register(context.Background(), appauth.RegisterInput{Email: "bee@example.com", Password: "supersecret"})
	if err != nil {
		t.Fatalf("Register: %v", err)
	}
	session, err := svc.SetupVerifyOTP(context.Background(), setup.SetupToken, genCode(t, setup.Secret))
	if err != nil {
		t.Fatalf("SetupVerifyOTP: %v", err)
	}

	err = svc.ChangePassword(context.Background(), session.UserID, appauth.ChangePasswordInput{
		CurrentPassword: "wrong-password",
		NewPassword:     "brandnewpassword",
		OTP:             genCode(t, setup.Secret),
	})
	if !errors.Is(err, appauth.ErrCurrentPasswordInvalid) {
		t.Fatalf("ChangePassword with wrong current password: got %v, want ErrCurrentPasswordInvalid", err)
	}

	if _, err := svc.Login(context.Background(), appauth.LoginInput{Email: "bee@example.com", Password: "supersecret"}); err != nil {
		t.Fatalf("Login with original password after failed change: %v", err)
	}
}

func TestChangePassword_WrongOTP_PasswordUnchanged(t *testing.T) {
	svc, _, _ := newTestService()
	setup, err := svc.Register(context.Background(), appauth.RegisterInput{Email: "bee@example.com", Password: "supersecret"})
	if err != nil {
		t.Fatalf("Register: %v", err)
	}
	session, err := svc.SetupVerifyOTP(context.Background(), setup.SetupToken, genCode(t, setup.Secret))
	if err != nil {
		t.Fatalf("SetupVerifyOTP: %v", err)
	}

	err = svc.ChangePassword(context.Background(), session.UserID, appauth.ChangePasswordInput{
		CurrentPassword: "supersecret",
		NewPassword:     "brandnewpassword",
		OTP:             "000000",
	})
	if !errors.Is(err, appauth.ErrOTPInvalid) {
		t.Fatalf("ChangePassword with wrong otp: got %v, want ErrOTPInvalid", err)
	}

	if _, err := svc.Login(context.Background(), appauth.LoginInput{Email: "bee@example.com", Password: "supersecret"}); err != nil {
		t.Fatalf("Login with original password after failed change: %v", err)
	}
}

// --- DeleteAccount ---

// TestDeleteAccount_Success proves the full cascade: a valid OTP unlocks
// it, apiary-service is asked to delete every apiary the caller owns
// (which, transitively, already reaches their hives, inspections, and
// media), then media-service is swept for anything left over (e.g. an
// avatar), then the user row itself is removed.
func TestDeleteAccount_Success(t *testing.T) {
	svc, _, media, apiaries := newTestServiceForDelete()
	setup, err := svc.Register(context.Background(), appauth.RegisterInput{Email: "bee@example.com", Password: "supersecret"})
	if err != nil {
		t.Fatalf("Register: %v", err)
	}
	session, err := svc.SetupVerifyOTP(context.Background(), setup.SetupToken, genCode(t, setup.Secret))
	if err != nil {
		t.Fatalf("SetupVerifyOTP: %v", err)
	}

	if err := svc.DeleteAccount(context.Background(), session.UserID, "access-token", genNextCode(t, setup.Secret)); err != nil {
		t.Fatalf("DeleteAccount: %v", err)
	}

	if !apiaries.called {
		t.Error("DeleteAccount did not cascade to apiary-service")
	}
	if !media.deleteAllCalled {
		t.Error("DeleteAccount did not sweep media-service")
	}
	if _, err := svc.CurrentUser(context.Background(), session.UserID); !errors.Is(err, user.ErrNotFound) {
		t.Fatalf("CurrentUser after DeleteAccount: got %v, want ErrNotFound", err)
	}
}

func TestDeleteAccount_UnknownUser(t *testing.T) {
	svc, _, media, apiaries := newTestServiceForDelete()

	if err := svc.DeleteAccount(context.Background(), uuid.New(), "access-token", "000000"); !errors.Is(err, user.ErrNotFound) {
		t.Fatalf("DeleteAccount for unknown user: got %v, want ErrNotFound", err)
	}
	if apiaries.called || media.deleteAllCalled {
		t.Error("DeleteAccount must not call downstream services for a user that doesn't exist")
	}
}

// TestDeleteAccount_WrongOTP_AccountSurvives proves knowing a valid access
// token is never sufficient on its own: a wrong OTP must reject the
// request before either downstream service is ever called, leaving the
// account (and everything it owns) completely untouched.
func TestDeleteAccount_WrongOTP_AccountSurvives(t *testing.T) {
	svc, _, media, apiaries := newTestServiceForDelete()
	setup, err := svc.Register(context.Background(), appauth.RegisterInput{Email: "bee@example.com", Password: "supersecret"})
	if err != nil {
		t.Fatalf("Register: %v", err)
	}
	session, err := svc.SetupVerifyOTP(context.Background(), setup.SetupToken, genCode(t, setup.Secret))
	if err != nil {
		t.Fatalf("SetupVerifyOTP: %v", err)
	}

	if err := svc.DeleteAccount(context.Background(), session.UserID, "access-token", "000000"); !errors.Is(err, appauth.ErrOTPInvalid) {
		t.Fatalf("DeleteAccount with wrong otp: got %v, want ErrOTPInvalid", err)
	}

	if apiaries.called || media.deleteAllCalled {
		t.Error("DeleteAccount must not call downstream services when the otp is wrong")
	}
	if _, err := svc.CurrentUser(context.Background(), session.UserID); err != nil {
		t.Fatalf("account should survive a wrong otp: %v", err)
	}
}

// TestDeleteAccount_AbortsOnApiaryCascadeFailure_AccountSurvives is the
// core abort-on-failure guarantee: if apiary-service can't be reached (or
// fails for any other reason), the account itself must not be deleted -
// otherwise its apiaries (and their hives/inspections/media) would be
// permanently orphaned, unreachable through any API but never actually
// removed.
func TestDeleteAccount_AbortsOnApiaryCascadeFailure_AccountSurvives(t *testing.T) {
	svc, _, media, apiaries := newTestServiceForDelete()
	setup, err := svc.Register(context.Background(), appauth.RegisterInput{Email: "bee@example.com", Password: "supersecret"})
	if err != nil {
		t.Fatalf("Register: %v", err)
	}
	session, err := svc.SetupVerifyOTP(context.Background(), setup.SetupToken, genCode(t, setup.Secret))
	if err != nil {
		t.Fatalf("SetupVerifyOTP: %v", err)
	}

	boom := errors.New("apiary-service unreachable")
	apiaries.failErr = boom

	if err := svc.DeleteAccount(context.Background(), session.UserID, "access-token", genNextCode(t, setup.Secret)); !errors.Is(err, boom) {
		t.Fatalf("DeleteAccount: got %v, want %v", err, boom)
	}

	if media.deleteAllCalled {
		t.Error("media-service was called even though apiary-service failed first")
	}
	if _, err := svc.CurrentUser(context.Background(), session.UserID); err != nil {
		t.Fatalf("account should survive when apiary-service fails: %v", err)
	}
}

// TestDeleteAccount_AbortsOnMediaSweepFailure_AccountSurvives mirrors the
// previous test for the second cascade step: media-service failing must
// also stop the account itself from being deleted, even though
// apiary-service's step already succeeded.
func TestDeleteAccount_AbortsOnMediaSweepFailure_AccountSurvives(t *testing.T) {
	svc, _, media, apiaries := newTestServiceForDelete()
	setup, err := svc.Register(context.Background(), appauth.RegisterInput{Email: "bee@example.com", Password: "supersecret"})
	if err != nil {
		t.Fatalf("Register: %v", err)
	}
	session, err := svc.SetupVerifyOTP(context.Background(), setup.SetupToken, genCode(t, setup.Secret))
	if err != nil {
		t.Fatalf("SetupVerifyOTP: %v", err)
	}

	boom := errors.New("media-service unreachable")
	media.deleteAllErr = boom

	if err := svc.DeleteAccount(context.Background(), session.UserID, "access-token", genNextCode(t, setup.Secret)); !errors.Is(err, boom) {
		t.Fatalf("DeleteAccount: got %v, want %v", err, boom)
	}

	if !apiaries.called {
		t.Error("apiary-service should have already been called before media-service failed")
	}
	if _, err := svc.CurrentUser(context.Background(), session.UserID); err != nil {
		t.Fatalf("account should survive when media-service fails: %v", err)
	}
}
