package auth_test

import (
	"context"
	"errors"
	"testing"

	appauth "github.com/sbezhuk/beebase-auth-service/internal/application/auth"
)

// This file extends session_cleanup_test.go's regression suite to the
// remaining flows that touch session/device cleanup or otherwise invoke
// verifyOTP/single-use-credential semantics: Logout, ChangePassword,
// forgot/reset password, and account deletion. See that file for the
// original TOTP-class bug (single-use credential consumed before the
// operation it gates has actually succeeded) and the shared
// cleanupSessionDevices mechanism this file's Logout tests reuse.

// --- Logout ---

// TestLogout_CleanupSucceeds_LogoutSucceeds covers the "cleanup succeeds"
// half of the Logout requirement: a normal logout, with notification-
// service healthy, must still revoke the refresh token, clear the active-
// session marker, and (eventually, best-effort) clean up device data.
func TestLogout_CleanupSucceeds_LogoutSucceeds(t *testing.T) {
	cleaner := newFakeSessionCleaner(nil)
	svc, users, sessions := newTestServiceWithCleanup(cleaner)

	setup, err := svc.Register(context.Background(), appauth.RegisterInput{Email: "bee@example.com", Password: "supersecret"})
	if err != nil {
		t.Fatalf("Register: %v", err)
	}
	session, err := svc.SetupVerifyOTP(context.Background(), setup.SetupToken, genCode(t, setup.Secret))
	if err != nil {
		t.Fatalf("SetupVerifyOTP: %v", err)
	}

	if err := svc.Logout(context.Background(), session.RefreshToken); err != nil {
		t.Fatalf("Logout: %v", err)
	}

	if _, err := svc.Refresh(context.Background(), session.RefreshToken); !errors.Is(err, appauth.ErrInvalidRefreshToken) {
		t.Fatalf("Refresh after logout: got %v, want ErrInvalidRefreshToken", err)
	}
	if sessions.HasActiveSession(session.UserID) {
		t.Error("Logout did not clear the active-session marker")
	}

	registeredUser, err := users.GetByEmail(context.Background(), "bee@example.com")
	if err != nil {
		t.Fatalf("GetByEmail: %v", err)
	}
	call := cleaner.waitForCall(t)
	if call.userID != registeredUser.ID {
		t.Errorf("DeleteSessionData called with user_id %v, want %v", call.userID, registeredUser.ID)
	}
}

// TestLogout_CleanupFails_LogoutStillSucceeds is the regression test for
// the known Logout bug: before this fix, Logout's own DeleteSessionData
// call was synchronous, so notification-service being unreachable turned
// an already-completed logout (refresh token already revoked, session
// already deactivated) into an HTTP-level failure. Logout must return
// success regardless, since the authentication session it's responsible
// for has already been correctly invalidated by the time cleanup runs.
func TestLogout_CleanupFails_LogoutStillSucceeds(t *testing.T) {
	cleaner := newFakeSessionCleaner(errNotificationServiceUnavailable)
	svc, _, sessions := newTestServiceWithCleanup(cleaner)

	setup, err := svc.Register(context.Background(), appauth.RegisterInput{Email: "bee@example.com", Password: "supersecret"})
	if err != nil {
		t.Fatalf("Register: %v", err)
	}
	session, err := svc.SetupVerifyOTP(context.Background(), setup.SetupToken, genCode(t, setup.Secret))
	if err != nil {
		t.Fatalf("SetupVerifyOTP: %v", err)
	}

	if err := svc.Logout(context.Background(), session.RefreshToken); err != nil {
		t.Fatalf("Logout with notification-service unavailable: got error %v, want nil (the auth session was already invalidated)", err)
	}

	// The security-critical part of logout must have happened regardless
	// of the cleanup failure: the token is revoked and the session marker
	// cleared exactly as in the success case.
	if _, err := svc.Refresh(context.Background(), session.RefreshToken); !errors.Is(err, appauth.ErrInvalidRefreshToken) {
		t.Fatalf("Refresh after logout: got %v, want ErrInvalidRefreshToken (logout must still revoke the session)", err)
	}
	if sessions.HasActiveSession(session.UserID) {
		t.Error("Logout did not clear the active-session marker despite cleanup failure")
	}

	// Confirm the failure path was actually exercised, not silently
	// skipped.
	cleaner.waitForCall(t)
}

// --- Change password ---

// TestChangePassword_Success_DeactivatesActiveSessionMarker closes a test-
// coverage gap: the pre-existing ChangePassword test only checks that the
// refresh token is revoked (via Refresh), never that the shared Redis
// active-session marker - what actually gates an already-issued, still-
// unexpired access token via authmw.Verifier - is cleared too. The
// production code already does this correctly; this locks it in.
func TestChangePassword_Success_DeactivatesActiveSessionMarker(t *testing.T) {
	svc, _, sessions := newTestServiceWithCleanup(newFakeSessionCleaner(nil))

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

	if sessions.HasActiveSession(session.UserID) {
		t.Error("ChangePassword did not clear the active-session marker")
	}
}

// TestChangePassword_PreviousSession_TriggersDeviceCleanupWithCorrectSessionID
// is the regression test for this change: ChangePassword must obtain the
// exact session id DeactivateAndReturnPrevious reports and hand it to
// cleanupSessionDevices - not some other id, not a zero value - so
// notification-service is asked to clean up the device data for the
// session that was actually just invalidated.
func TestChangePassword_PreviousSession_TriggersDeviceCleanupWithCorrectSessionID(t *testing.T) {
	cleaner := newFakeSessionCleaner(nil)
	svc, users, sessions := newTestServiceWithCleanup(cleaner)

	setup, err := svc.Register(context.Background(), appauth.RegisterInput{Email: "bee@example.com", Password: "supersecret"})
	if err != nil {
		t.Fatalf("Register: %v", err)
	}
	if _, err := svc.SetupVerifyOTP(context.Background(), setup.SetupToken, genCode(t, setup.Secret)); err != nil {
		t.Fatalf("SetupVerifyOTP: %v", err)
	}
	registeredUser, err := users.GetByEmail(context.Background(), "bee@example.com")
	if err != nil {
		t.Fatalf("GetByEmail: %v", err)
	}
	wantSessionID, ok := sessions.activeSessionID(registeredUser.ID)
	if !ok {
		t.Fatal("test setup: expected an active session after SetupVerifyOTP")
	}

	if err := svc.ChangePassword(context.Background(), registeredUser.ID, appauth.ChangePasswordInput{
		CurrentPassword: "supersecret",
		NewPassword:     "brandnewpassword",
		OTP:             genNextCode(t, setup.Secret),
	}); err != nil {
		t.Fatalf("ChangePassword: %v", err)
	}

	call := cleaner.waitForCall(t)
	if call.userID != registeredUser.ID {
		t.Errorf("DeleteSessionData called with user_id %v, want %v", call.userID, registeredUser.ID)
	}
	if call.previousSessionID != wantSessionID {
		t.Errorf("DeleteSessionData called with previous_session_id %v, want %v (the session ChangePassword actually invalidated)", call.previousSessionID, wantSessionID)
	}
}

// TestChangePassword_CleanupFails_ChangePasswordStillSucceeds proves
// ChangePassword's own success no longer depends on notification-service:
// the password mutation and session revocation (both security-critical)
// have already fully committed by the time the best-effort cleanup call
// even runs.
func TestChangePassword_CleanupFails_ChangePasswordStillSucceeds(t *testing.T) {
	cleaner := newFakeSessionCleaner(errNotificationServiceUnavailable)
	svc, _, sessions := newTestServiceWithCleanup(cleaner)

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
		t.Fatalf("ChangePassword with notification-service unavailable: got error %v, want nil", err)
	}

	if _, err := svc.Refresh(context.Background(), session.RefreshToken); !errors.Is(err, appauth.ErrInvalidRefreshToken) {
		t.Fatalf("Refresh after password change: got %v, want ErrInvalidRefreshToken", err)
	}
	if sessions.HasActiveSession(session.UserID) {
		t.Error("ChangePassword did not clear the active-session marker despite cleanup failure")
	}
	if _, err := svc.Login(context.Background(), appauth.LoginInput{Email: "bee@example.com", Password: "brandnewpassword"}); err != nil {
		t.Fatalf("Login with the new password: %v", err)
	}

	cleaner.waitForCall(t)
}

// TestChangePassword_NoActiveSession_SucceedsWithoutCleanup covers the
// hadPrevious=false branch: an account whose session already expired (or
// was already logged out) naturally has nothing for
// DeactivateAndReturnPrevious to report, and ChangePassword must not
// invoke cleanup in that case.
func TestChangePassword_NoActiveSession_SucceedsWithoutCleanup(t *testing.T) {
	cleaner := newFakeSessionCleaner(nil)
	svc, users, sessions := newTestServiceWithCleanup(cleaner)

	setup, err := svc.Register(context.Background(), appauth.RegisterInput{Email: "bee@example.com", Password: "supersecret"})
	if err != nil {
		t.Fatalf("Register: %v", err)
	}
	session, err := svc.SetupVerifyOTP(context.Background(), setup.SetupToken, genCode(t, setup.Secret))
	if err != nil {
		t.Fatalf("SetupVerifyOTP: %v", err)
	}
	registeredUser, err := users.GetByEmail(context.Background(), "bee@example.com")
	if err != nil {
		t.Fatalf("GetByEmail: %v", err)
	}
	if err := sessions.Deactivate(context.Background(), registeredUser.ID); err != nil {
		t.Fatalf("simulate an already-expired/logged-out session: %v", err)
	}

	if err := svc.ChangePassword(context.Background(), session.UserID, appauth.ChangePasswordInput{
		CurrentPassword: "supersecret",
		NewPassword:     "brandnewpassword",
		OTP:             genNextCode(t, setup.Secret),
	}); err != nil {
		t.Fatalf("ChangePassword with no active session: %v", err)
	}

	cleaner.assertNeverCalled(t)
}

// --- Forgot / reset password ---

// TestConfirmPasswordReset_Success_DeactivatesActiveSessionMarker is the
// regression test for the vulnerability found in this audit:
// ConfirmPasswordReset revoked refresh tokens in Postgres but never
// cleared the Redis active-session marker, so a pre-reset access token
// stayed valid (accepted by every service's authmw.Verifier) for up to
// its own remaining ~15 minute JWT lifetime after a password reset -
// exactly the sessions BEEB-34 says a password recovery must invalidate.
func TestConfirmPasswordReset_Success_DeactivatesActiveSessionMarker(t *testing.T) {
	svc, _, sessions := newTestServiceWithCleanup(newFakeSessionCleaner(nil))

	setup, err := svc.Register(context.Background(), appauth.RegisterInput{Email: "bee@example.com", Password: "supersecret"})
	if err != nil {
		t.Fatalf("Register: %v", err)
	}
	session, err := svc.SetupVerifyOTP(context.Background(), setup.SetupToken, genCode(t, setup.Secret))
	if err != nil {
		t.Fatalf("SetupVerifyOTP: %v", err)
	}
	if !sessions.HasActiveSession(session.UserID) {
		t.Fatal("test setup: expected an active session marker after SetupVerifyOTP")
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

	if sessions.HasActiveSession(session.UserID) {
		t.Error("ConfirmPasswordReset did not clear the active-session marker - a pre-reset access token would stay valid until its own JWT expiry")
	}
}

// TestConfirmPasswordReset_UpdatePasswordFails_TokenNotConsumed_RetrySucceeds
// is the TOTP-class-bug check for password reset: the reset token must
// only be marked consumed once the password mutation it gates has
// actually succeeded. This injects a failure into the mutation step
// itself (fakeUserRepo.UpdatePassword) - which runs *before*
// flow.Consume() in the current, correct ordering - and confirms the
// reset token survives untouched, so a legitimate retry with the same
// token still works, rather than coming back
// ErrPasswordResetTokenInvalid the way a prematurely-consumed credential
// would.
func TestConfirmPasswordReset_UpdatePasswordFails_TokenNotConsumed_RetrySucceeds(t *testing.T) {
	svc, users, _ := newTestServiceWithCleanup(newFakeSessionCleaner(nil))

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

	users.failNextUpdatePassword(errors.New("db: connection reset"))

	if err := svc.ConfirmPasswordReset(context.Background(), otpResult.ResetToken, "firstattempt1!"); err == nil {
		t.Fatal("ConfirmPasswordReset: want an error from the injected UpdatePassword failure, got nil")
	}

	// Retry with the SAME reset token. Before this would be safe to rely
	// on, it needed proving: the token must not have been burned by the
	// failed attempt above.
	if err := svc.ConfirmPasswordReset(context.Background(), otpResult.ResetToken, "secondattempt1!"); err != nil {
		t.Fatalf("retry ConfirmPasswordReset after UpdatePassword failure: got %v, want success (the reset token must survive an unrelated mutation failure)", err)
	}

	if _, err := svc.Login(context.Background(), appauth.LoginInput{Email: "bee@example.com", Password: "secondattempt1!"}); err != nil {
		t.Fatalf("Login with the password set by the retry: %v", err)
	}
}

// TestConfirmPasswordReset_PreviousSession_TriggersDeviceCleanupWithCorrectSessionID
// mirrors TestChangePassword_PreviousSession_TriggersDeviceCleanupWithCorrectSessionID
// for the reset-password path: the pre-reset session's exact id must
// reach cleanupSessionDevices.
func TestConfirmPasswordReset_PreviousSession_TriggersDeviceCleanupWithCorrectSessionID(t *testing.T) {
	cleaner := newFakeSessionCleaner(nil)
	svc, users, sessions := newTestServiceWithCleanup(cleaner)

	setup, err := svc.Register(context.Background(), appauth.RegisterInput{Email: "bee@example.com", Password: "supersecret"})
	if err != nil {
		t.Fatalf("Register: %v", err)
	}
	if _, err := svc.SetupVerifyOTP(context.Background(), setup.SetupToken, genCode(t, setup.Secret)); err != nil {
		t.Fatalf("SetupVerifyOTP: %v", err)
	}
	registeredUser, err := users.GetByEmail(context.Background(), "bee@example.com")
	if err != nil {
		t.Fatalf("GetByEmail: %v", err)
	}
	wantSessionID, ok := sessions.activeSessionID(registeredUser.ID)
	if !ok {
		t.Fatal("test setup: expected an active session after SetupVerifyOTP")
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

	call := cleaner.waitForCall(t)
	if call.userID != registeredUser.ID {
		t.Errorf("DeleteSessionData called with user_id %v, want %v", call.userID, registeredUser.ID)
	}
	if call.previousSessionID != wantSessionID {
		t.Errorf("DeleteSessionData called with previous_session_id %v, want %v (the session ConfirmPasswordReset actually invalidated)", call.previousSessionID, wantSessionID)
	}
}

// TestConfirmPasswordReset_CleanupFails_ResetStillSucceeds proves
// ConfirmPasswordReset's own success no longer depends on notification-
// service: the password mutation, reset-token consumption, and session
// revocation have all already fully committed by the time the
// best-effort cleanup call runs.
func TestConfirmPasswordReset_CleanupFails_ResetStillSucceeds(t *testing.T) {
	cleaner := newFakeSessionCleaner(errNotificationServiceUnavailable)
	svc, _, sessions := newTestServiceWithCleanup(cleaner)

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
		t.Fatalf("ConfirmPasswordReset with notification-service unavailable: got error %v, want nil", err)
	}

	if _, err := svc.Refresh(context.Background(), session.RefreshToken); !errors.Is(err, appauth.ErrInvalidRefreshToken) {
		t.Fatalf("Refresh with pre-reset token: got %v, want ErrInvalidRefreshToken", err)
	}
	if sessions.HasActiveSession(session.UserID) {
		t.Error("ConfirmPasswordReset did not clear the active-session marker despite cleanup failure")
	}
	// Reset credential remains single-use regardless of the cleanup
	// failure that happens after it.
	if err := svc.ConfirmPasswordReset(context.Background(), otpResult.ResetToken, "anotherpassword"); !errors.Is(err, appauth.ErrPasswordResetTokenInvalid) {
		t.Fatalf("replayed ConfirmPasswordReset: got %v, want ErrPasswordResetTokenInvalid", err)
	}

	cleaner.waitForCall(t)
}

// TestConfirmPasswordReset_NoActiveSession_Succeeds covers the
// hadPrevious=false branch for the reset-password path: an account with
// no active session (already expired or logged out) has nothing for
// DeactivateAndReturnPrevious to report, and reset must succeed without
// invoking cleanup.
func TestConfirmPasswordReset_NoActiveSession_Succeeds(t *testing.T) {
	cleaner := newFakeSessionCleaner(nil)
	svc, users, sessions := newTestServiceWithCleanup(cleaner)

	setup, err := svc.Register(context.Background(), appauth.RegisterInput{Email: "bee@example.com", Password: "supersecret"})
	if err != nil {
		t.Fatalf("Register: %v", err)
	}
	if _, err := svc.SetupVerifyOTP(context.Background(), setup.SetupToken, genCode(t, setup.Secret)); err != nil {
		t.Fatalf("SetupVerifyOTP: %v", err)
	}
	registeredUser, err := users.GetByEmail(context.Background(), "bee@example.com")
	if err != nil {
		t.Fatalf("GetByEmail: %v", err)
	}
	if err := sessions.Deactivate(context.Background(), registeredUser.ID); err != nil {
		t.Fatalf("simulate an already-expired/logged-out session: %v", err)
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
		t.Fatalf("ConfirmPasswordReset with no active session: %v", err)
	}

	cleaner.assertNeverCalled(t)
}

// --- Account deletion ---

// TestDeleteAccount_DurableJobPath_SucceedsRegardlessOfDownstreamServices
// proves DeleteAccount, when wired with a DeletionRequester (the actual
// production shape - see cmd/server/main.go's sessionCleanupRequester),
// takes the durable-job path: it creates the job and immediately revokes
// the account's authentication state, without ever synchronously calling
// apiary-service, media-service, or notification-service. Every
// pre-existing DeleteAccount test in service_totp_test.go exercises only
// the legacy direct-cascade fallback (no DeletionRequester passed), which
// is unreachable in production - this closes that coverage gap.
func TestDeleteAccount_DurableJobPath_SucceedsRegardlessOfDownstreamServices(t *testing.T) {
	deletion := newFakeDeletionRequester(nil)
	svc, _, sessions, media, apiaries := newTestServiceForDeleteWithDeletionRequester(deletion)

	setup, err := svc.Register(context.Background(), appauth.RegisterInput{Email: "bee@example.com", Password: "supersecret"})
	if err != nil {
		t.Fatalf("Register: %v", err)
	}
	session, err := svc.SetupVerifyOTP(context.Background(), setup.SetupToken, genCode(t, setup.Secret))
	if err != nil {
		t.Fatalf("SetupVerifyOTP: %v", err)
	}

	if err := svc.DeleteAccount(context.Background(), session.UserID, "access-token", genNextCode(t, setup.Secret)); err != nil {
		t.Fatalf("DeleteAccount: got error %v, want success - the durable job path never calls a downstream service synchronously", err)
	}

	if !deletion.calledWith(session.UserID) {
		t.Error("DeleteAccount did not create a durable deletion job (RequestDeletion was never called)")
	}
	if apiaries.called {
		t.Error("DeleteAccount called apiary-service directly - the durable job path must leave per-service cleanup to the DeletionWorker")
	}
	if media.deleteAllCalled {
		t.Error("DeleteAccount called media-service directly - the durable job path must leave per-service cleanup to the DeletionWorker")
	}

	if _, err := svc.Refresh(context.Background(), session.RefreshToken); !errors.Is(err, appauth.ErrInvalidRefreshToken) {
		t.Fatalf("Refresh after account deletion: got %v, want ErrInvalidRefreshToken (session must be revoked immediately, not deferred to the worker)", err)
	}
	if sessions.HasActiveSession(session.UserID) {
		t.Error("DeleteAccount did not clear the active-session marker immediately")
	}
}

// TestDeleteAccount_DurableJobPath_RequestDeletionFails_AccountSurvives
// covers "failure of a genuinely required deletion step is still surfaced
// correctly": unlike notification cleanup, RequestDeletion durably
// recording the deletion request is itself the security/consistency-
// critical step for this path (it's what makes the account unusable and
// creates the steps DeletionWorker will later drive to completion) - so
// its failure must still abort the request and leave the account and its
// authentication state completely untouched, the same "abort on failure,
// account survives" guarantee the legacy cascade tests already establish
// for apiary-service/media-service.
func TestDeleteAccount_DurableJobPath_RequestDeletionFails_AccountSurvives(t *testing.T) {
	boom := errors.New("postgres: connection refused")
	deletion := newFakeDeletionRequester(boom)
	svc, _, _, media, apiaries := newTestServiceForDeleteWithDeletionRequester(deletion)

	setup, err := svc.Register(context.Background(), appauth.RegisterInput{Email: "bee@example.com", Password: "supersecret"})
	if err != nil {
		t.Fatalf("Register: %v", err)
	}
	session, err := svc.SetupVerifyOTP(context.Background(), setup.SetupToken, genCode(t, setup.Secret))
	if err != nil {
		t.Fatalf("SetupVerifyOTP: %v", err)
	}

	if err := svc.DeleteAccount(context.Background(), session.UserID, "access-token", genNextCode(t, setup.Secret)); !errors.Is(err, boom) {
		t.Fatalf("DeleteAccount: got %v, want %v", err, boom)
	}

	if apiaries.called || media.deleteAllCalled {
		t.Error("DeleteAccount must not fall back to the legacy cascade when RequestDeletion fails")
	}
	if _, err := svc.Refresh(context.Background(), session.RefreshToken); err != nil {
		t.Fatalf("Refresh after a failed deletion request: got %v, want success (the account/session must survive untouched)", err)
	}
}
