package auth_test

import (
	"context"
	"errors"
	"testing"

	appauth "github.com/sbezhuk/beebase-auth-service/internal/application/auth"
)

func mustRegisterUnverified(t *testing.T, svc *appauth.Service, email, pw string) {
	t.Helper()
	if _, err := svc.Register(context.Background(), appauth.RegisterInput{Email: email, Password: pw}); err != nil {
		t.Fatalf("Register: %v", err)
	}
}

// --- RequestPasswordReset ---

func TestRequestPasswordReset_SameShapeForKnownAndUnknownEmail(t *testing.T) {
	svc, _, _ := newTestService()
	mustRegisterUnverified(t, svc, "known-no-2fa@example.com", "supersecret")

	knownResult, err := svc.RequestPasswordReset(context.Background(), "known-no-2fa@example.com")
	if err != nil {
		t.Fatalf("RequestPasswordReset(known, ineligible): %v", err)
	}
	unknownResult, err := svc.RequestPasswordReset(context.Background(), "nobody@example.com")
	if err != nil {
		t.Fatalf("RequestPasswordReset(unknown): %v", err)
	}

	if knownResult.FlowToken == "" || unknownResult.FlowToken == "" {
		t.Fatal("RequestPasswordReset did not return a flow token in both cases")
	}
}

func TestRequestPasswordReset_EligibleAccount(t *testing.T) {
	svc, _, _ := newTestService()
	mustRegister(t, svc, "bee@example.com", "supersecret")

	result, err := svc.RequestPasswordReset(context.Background(), "bee@example.com")
	if err != nil {
		t.Fatalf("RequestPasswordReset: %v", err)
	}
	if result.FlowToken == "" {
		t.Fatal("RequestPasswordReset did not return a flow token")
	}
}

// --- VerifyPasswordResetOTP ---

func TestVerifyPasswordResetOTP_IneligibleFlow_GenericFailure(t *testing.T) {
	svc, _, _ := newTestService()
	mustRegisterUnverified(t, svc, "known-no-2fa@example.com", "supersecret")

	result, err := svc.RequestPasswordReset(context.Background(), "known-no-2fa@example.com")
	if err != nil {
		t.Fatalf("RequestPasswordReset: %v", err)
	}

	if _, err := svc.VerifyPasswordResetOTP(context.Background(), result.FlowToken, "123456"); !errors.Is(err, appauth.ErrOTPInvalid) {
		t.Fatalf("VerifyPasswordResetOTP on ineligible flow: got %v, want ErrOTPInvalid", err)
	}
}

func TestVerifyPasswordResetOTP_UnknownEmail_GenericFailure(t *testing.T) {
	svc, _, _ := newTestService()

	result, err := svc.RequestPasswordReset(context.Background(), "nobody@example.com")
	if err != nil {
		t.Fatalf("RequestPasswordReset: %v", err)
	}

	if _, err := svc.VerifyPasswordResetOTP(context.Background(), result.FlowToken, "123456"); !errors.Is(err, appauth.ErrOTPInvalid) {
		t.Fatalf("VerifyPasswordResetOTP for unknown email's flow: got %v, want ErrOTPInvalid", err)
	}
}

func TestVerifyPasswordResetOTP_Success(t *testing.T) {
	svc, _, _ := newTestService()
	setup, err := svc.Register(context.Background(), appauth.RegisterInput{Email: "bee@example.com", Password: "supersecret"})
	if err != nil {
		t.Fatalf("Register: %v", err)
	}
	if _, err := svc.SetupVerifyOTP(context.Background(), setup.SetupToken, genCode(t, setup.Secret)); err != nil {
		t.Fatalf("SetupVerifyOTP: %v", err)
	}

	resetResult, err := svc.RequestPasswordReset(context.Background(), "bee@example.com")
	if err != nil {
		t.Fatalf("RequestPasswordReset: %v", err)
	}

	otpResult, err := svc.VerifyPasswordResetOTP(context.Background(), resetResult.FlowToken, genNextCode(t, setup.Secret))
	if err != nil {
		t.Fatalf("VerifyPasswordResetOTP: %v", err)
	}
	if otpResult.ResetToken == "" {
		t.Fatal("VerifyPasswordResetOTP did not return a reset token")
	}
}

// TestVerifyPasswordResetOTP_WrongOTP_DoesNotLockAccount guards against a
// real griefing bug considered during design: an unauthenticated attacker
// who only knows a victim's email must never be able to lock the victim
// out of logging in by burning through forgot-password OTP guesses.
func TestVerifyPasswordResetOTP_WrongOTP_DoesNotLockAccount(t *testing.T) {
	svc, _, _ := newTestService()
	setup, err := svc.Register(context.Background(), appauth.RegisterInput{Email: "bee@example.com", Password: "supersecret"})
	if err != nil {
		t.Fatalf("Register: %v", err)
	}
	if _, err := svc.SetupVerifyOTP(context.Background(), setup.SetupToken, genCode(t, setup.Secret)); err != nil {
		t.Fatalf("SetupVerifyOTP: %v", err)
	}

	resetResult, err := svc.RequestPasswordReset(context.Background(), "bee@example.com")
	if err != nil {
		t.Fatalf("RequestPasswordReset: %v", err)
	}

	for i := 0; i < 5; i++ {
		if _, err := svc.VerifyPasswordResetOTP(context.Background(), resetResult.FlowToken, "000000"); err == nil {
			t.Fatalf("attempt #%d: wrong code unexpectedly succeeded", i)
		}
	}

	// The real account's own lockout must be untouched: a fresh login
	// challenge with the correct code must still succeed immediately.
	login, err := svc.Login(context.Background(), appauth.LoginInput{Email: "bee@example.com", Password: "supersecret"})
	if err != nil {
		t.Fatalf("Login: %v", err)
	}
	if _, err := svc.LoginVerifyOTP(context.Background(), login.ChallengeToken, genNextCode(t, setup.Secret)); err != nil {
		t.Fatalf("LoginVerifyOTP after forgot-password guesses: got %v, want success (account lockout must be independent)", err)
	}
}

func TestVerifyPasswordResetOTP_FlowLockedAfterMaxAttempts(t *testing.T) {
	svc, _, _ := newTestService()
	setup, err := svc.Register(context.Background(), appauth.RegisterInput{Email: "bee@example.com", Password: "supersecret"})
	if err != nil {
		t.Fatalf("Register: %v", err)
	}
	if _, err := svc.SetupVerifyOTP(context.Background(), setup.SetupToken, genCode(t, setup.Secret)); err != nil {
		t.Fatalf("SetupVerifyOTP: %v", err)
	}

	resetResult, err := svc.RequestPasswordReset(context.Background(), "bee@example.com")
	if err != nil {
		t.Fatalf("RequestPasswordReset: %v", err)
	}

	// newTestSecurityConfig sets ResetFlowMaxOTPAttempts to 5.
	for i := 0; i < 5; i++ {
		_, _ = svc.VerifyPasswordResetOTP(context.Background(), resetResult.FlowToken, "000000")
	}

	if _, err := svc.VerifyPasswordResetOTP(context.Background(), resetResult.FlowToken, genCode(t, setup.Secret)); !errors.Is(err, appauth.ErrOTPLocked) {
		t.Fatalf("VerifyPasswordResetOTP with valid code after exhausting flow attempts: got %v, want ErrOTPLocked", err)
	}
}

// --- ConfirmPasswordReset ---

func TestConfirmPasswordReset_WithoutOTPVerify_Rejected(t *testing.T) {
	svc, _, _ := newTestService()
	setup, err := svc.Register(context.Background(), appauth.RegisterInput{Email: "bee@example.com", Password: "supersecret"})
	if err != nil {
		t.Fatalf("Register: %v", err)
	}
	if _, err := svc.SetupVerifyOTP(context.Background(), setup.SetupToken, genCode(t, setup.Secret)); err != nil {
		t.Fatalf("SetupVerifyOTP: %v", err)
	}

	resetResult, err := svc.RequestPasswordReset(context.Background(), "bee@example.com")
	if err != nil {
		t.Fatalf("RequestPasswordReset: %v", err)
	}

	// The flow token from request-reset is not a reset token: confirm must
	// reject it outright, since the OTP step was never completed.
	if err := svc.ConfirmPasswordReset(context.Background(), resetResult.FlowToken, "brandnewpassword"); !errors.Is(err, appauth.ErrPasswordResetTokenInvalid) {
		t.Fatalf("ConfirmPasswordReset without OTP verify: got %v, want ErrPasswordResetTokenInvalid", err)
	}
}

func TestConfirmPasswordReset_UnknownToken(t *testing.T) {
	svc, _, _ := newTestService()

	if err := svc.ConfirmPasswordReset(context.Background(), "not-a-real-token", "brandnewpassword"); !errors.Is(err, appauth.ErrPasswordResetTokenInvalid) {
		t.Fatalf("ConfirmPasswordReset with unknown token: got %v, want ErrPasswordResetTokenInvalid", err)
	}
}

func TestConfirmPasswordReset_Success_SingleUseAndRevokesSessions(t *testing.T) {
	svc, _, _ := newTestService()
	setup, err := svc.Register(context.Background(), appauth.RegisterInput{Email: "bee@example.com", Password: "supersecret"})
	if err != nil {
		t.Fatalf("Register: %v", err)
	}
	session, err := svc.SetupVerifyOTP(context.Background(), setup.SetupToken, genCode(t, setup.Secret))
	if err != nil {
		t.Fatalf("SetupVerifyOTP: %v", err)
	}

	resetResult, err := svc.RequestPasswordReset(context.Background(), "bee@example.com")
	if err != nil {
		t.Fatalf("RequestPasswordReset: %v", err)
	}
	otpResult, err := svc.VerifyPasswordResetOTP(context.Background(), resetResult.FlowToken, genNextCode(t, setup.Secret))
	if err != nil {
		t.Fatalf("VerifyPasswordResetOTP: %v", err)
	}

	if err := svc.ConfirmPasswordReset(context.Background(), otpResult.ResetToken, "brandnewpassword"); err != nil {
		t.Fatalf("ConfirmPasswordReset: %v", err)
	}

	if err := svc.ConfirmPasswordReset(context.Background(), otpResult.ResetToken, "yetanotherpassword"); !errors.Is(err, appauth.ErrPasswordResetTokenInvalid) {
		t.Fatalf("replayed ConfirmPasswordReset: got %v, want ErrPasswordResetTokenInvalid", err)
	}

	if _, err := svc.Refresh(context.Background(), session.RefreshToken); !errors.Is(err, appauth.ErrInvalidRefreshToken) {
		t.Fatalf("Refresh with pre-reset token: got %v, want ErrInvalidRefreshToken", err)
	}

	if _, err := svc.Login(context.Background(), appauth.LoginInput{Email: "bee@example.com", Password: "brandnewpassword"}); err != nil {
		t.Fatalf("Login with new password: %v", err)
	}
}
