package auth_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"

	appauth "github.com/sbezhuk/beebase-auth-service/internal/application/auth"
)

// This file is the regression suite for the "notification-service outage
// breaks re-authentication" bug: issueSession used to call
// notification-service synchronously to clean up a superseded session's
// device data whenever hadPrevious was true, and a failure there aborted
// session issuance entirely - including from LoginVerifyOTP, which had
// already consumed the (single-use) login challenge by that point. A
// user whose access token had merely expired (not been logged out) would
// then get a 500 on a perfectly valid TOTP code, and a same-challenge
// retry would come back "invalid or expired login challenge" - reading,
// from the client's side, exactly like an expired session. See
// issueSession/cleanupSessionDevices in service.go and the
// reordering in service_totp.go for the fix.

var errNotificationServiceUnavailable = errors.New("dial tcp: lookup notification-service: no such host")

// waitForNextTOTPPeriod blocks until the next 30-second TOTP time-step
// boundary (plus a small buffer), so a subsequent genCode call is
// guaranteed to produce a code with a higher anti-replay counter than one
// already consumed in the current period - the real-world equivalent of a
// user's authenticator app rolling over to a new code. TOTP's own 30s
// granularity, not this test, sets the bound on how fast this can be.
func waitForNextTOTPPeriod(t *testing.T) {
	t.Helper()
	const period = 30 * time.Second
	now := time.Now().UTC()
	wait := period - now.Sub(now.Truncate(period)) + time.Second
	time.Sleep(wait)
}

// TestIssueSession_PreviousSession_CleanupSucceeds covers requirement 1:
// hadPrevious=true, cleanup succeeds -> session issuance succeeds, and the
// cleanup dependency is actually invoked with the right user/session.
func TestIssueSession_PreviousSession_CleanupSucceeds(t *testing.T) {
	cleaner := newFakeSessionCleaner(nil)
	svc, users, _ := newTestServiceWithCleanup(cleaner)

	setup, err := svc.Register(context.Background(), appauth.RegisterInput{Email: "bee@example.com", Password: "supersecret"})
	if err != nil {
		t.Fatalf("Register: %v", err)
	}
	if _, err := svc.SetupVerifyOTP(context.Background(), setup.SetupToken, genCode(t, setup.Secret)); err != nil {
		t.Fatalf("SetupVerifyOTP (first session): %v", err)
	}

	login, err := svc.Login(context.Background(), appauth.LoginInput{Email: "bee@example.com", Password: "supersecret"})
	if err != nil {
		t.Fatalf("Login: %v", err)
	}
	second, err := svc.LoginVerifyOTP(context.Background(), login.ChallengeToken, genNextCode(t, setup.Secret))
	if err != nil {
		t.Fatalf("LoginVerifyOTP (second session, hadPrevious=true): %v", err)
	}
	if second.AccessToken == "" || second.RefreshToken == "" {
		t.Error("LoginVerifyOTP did not issue a full session")
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

// TestIssueSession_PreviousSession_CleanupFails_SessionStillIssued covers
// requirements 2 and 5: hadPrevious=true, DeleteSessionData fails (as it
// would with notification-service unreachable) -> LoginVerifyOTP must
// still succeed with a valid TOTP, returning a real session rather than
// the 500 the pre-fix code produced.
func TestIssueSession_PreviousSession_CleanupFails_SessionStillIssued(t *testing.T) {
	cleaner := newFakeSessionCleaner(errNotificationServiceUnavailable)
	svc, _, _ := newTestServiceWithCleanup(cleaner)

	setup, err := svc.Register(context.Background(), appauth.RegisterInput{Email: "bee@example.com", Password: "supersecret"})
	if err != nil {
		t.Fatalf("Register: %v", err)
	}
	first, err := svc.SetupVerifyOTP(context.Background(), setup.SetupToken, genCode(t, setup.Secret))
	if err != nil {
		t.Fatalf("SetupVerifyOTP (first session): %v", err)
	}

	// Simulates "expired session -> login -> TOTP": a fresh login+OTP
	// cycle against an account that already has an active (not explicitly
	// logged-out) session, i.e. hadPrevious=true on the session about to
	// be issued.
	login, err := svc.Login(context.Background(), appauth.LoginInput{Email: "bee@example.com", Password: "supersecret"})
	if err != nil {
		t.Fatalf("Login: %v", err)
	}
	second, err := svc.LoginVerifyOTP(context.Background(), login.ChallengeToken, genNextCode(t, setup.Secret))
	if err != nil {
		t.Fatalf("LoginVerifyOTP with notification-service unavailable: got error %v, want a valid session (cleanup failure must not fail authentication)", err)
	}
	if second.AccessToken == "" || second.RefreshToken == "" {
		t.Error("LoginVerifyOTP did not issue a full session despite cleanup failure")
	}
	if second.RefreshToken == first.RefreshToken {
		t.Error("second session reused the first session's refresh token")
	}

	// Confirm the failure path was actually exercised, not silently
	// skipped - a green test here must mean the fix works, not that
	// DeleteSessionData was never called.
	cleaner.waitForCall(t)
}

// TestIssueSession_NoPreviousSession_CleanupNeverInvoked covers
// requirement 3: a brand new account's very first session has no previous
// session to clean up, so the cleanup dependency must not be invoked at
// all - session issuance behavior here is completely unaffected by this
// change.
func TestIssueSession_NoPreviousSession_CleanupNeverInvoked(t *testing.T) {
	cleaner := newFakeSessionCleaner(nil)
	svc, _, _ := newTestServiceWithCleanup(cleaner)

	setup, err := svc.Register(context.Background(), appauth.RegisterInput{Email: "bee@example.com", Password: "supersecret"})
	if err != nil {
		t.Fatalf("Register: %v", err)
	}
	session, err := svc.SetupVerifyOTP(context.Background(), setup.SetupToken, genCode(t, setup.Secret))
	if err != nil {
		t.Fatalf("SetupVerifyOTP: %v", err)
	}
	if session.AccessToken == "" {
		t.Fatal("SetupVerifyOTP did not issue a session")
	}

	cleaner.assertNeverCalled(t)
}

// TestRefresh_SucceedsDespiteCleanupFailure covers requirement 4 and the
// "expired access token -> refresh -> notification-service unavailable"
// behavioral regression: Refresh also goes through issueSession, and its
// "previous" session is always the very one being refreshed (hadPrevious
// is true on essentially every refresh), so a notification-service outage
// must not break ordinary silent token refresh either.
func TestRefresh_SucceedsDespiteCleanupFailure(t *testing.T) {
	cleaner := newFakeSessionCleaner(errNotificationServiceUnavailable)
	svc, _, _ := newTestServiceWithCleanup(cleaner)

	setup, err := svc.Register(context.Background(), appauth.RegisterInput{Email: "bee@example.com", Password: "supersecret"})
	if err != nil {
		t.Fatalf("Register: %v", err)
	}
	session, err := svc.SetupVerifyOTP(context.Background(), setup.SetupToken, genCode(t, setup.Secret))
	if err != nil {
		t.Fatalf("SetupVerifyOTP: %v", err)
	}
	// The setup-verify session itself is hadPrevious=false, so drain that
	// (absent) call before refreshing, to keep this test's own assertions
	// unambiguous about which cleanup call they're observing.

	refreshed, err := svc.Refresh(context.Background(), session.RefreshToken)
	if err != nil {
		t.Fatalf("Refresh with notification-service unavailable: got error %v, want a valid new session", err)
	}
	if refreshed.AccessToken == "" || refreshed.RefreshToken == "" {
		t.Error("Refresh did not issue valid new tokens despite cleanup failure")
	}
	if refreshed.RefreshToken == session.RefreshToken {
		t.Error("Refresh did not rotate the refresh token")
	}

	cleaner.waitForCall(t)
}

// TestSetupVerifyOTP_PreviousSessionCleanupFails_SessionStillIssued covers
// requirement 6. In practice SetupVerifyOTP's challenge is only ever
// reachable before a credential is enabled, so a genuine prior session is
// effectively impossible to reach through the public API alone - but
// issueSession's cleanup call doesn't know or care which caller reached
// it, so this primes hadPrevious=true directly on the fake session store
// to exercise the same shared code path SetupVerifyOTP runs through.
func TestSetupVerifyOTP_PreviousSessionCleanupFails_SessionStillIssued(t *testing.T) {
	cleaner := newFakeSessionCleaner(errNotificationServiceUnavailable)
	svc, users, sessions := newTestServiceWithCleanup(cleaner)

	setup, err := svc.Register(context.Background(), appauth.RegisterInput{Email: "bee@example.com", Password: "supersecret"})
	if err != nil {
		t.Fatalf("Register: %v", err)
	}
	registeredUser, err := users.GetByEmail(context.Background(), "bee@example.com")
	if err != nil {
		t.Fatalf("GetByEmail: %v", err)
	}
	if err := sessions.Activate(context.Background(), registeredUser.ID, uuid.New(), time.Hour); err != nil {
		t.Fatalf("prime prior session: %v", err)
	}

	session, err := svc.SetupVerifyOTP(context.Background(), setup.SetupToken, genCode(t, setup.Secret))
	if err != nil {
		t.Fatalf("SetupVerifyOTP with notification-service unavailable: got error %v, want a valid session", err)
	}
	if session.AccessToken == "" || session.RefreshToken == "" {
		t.Error("SetupVerifyOTP did not issue a full session despite cleanup failure")
	}

	cleaner.waitForCall(t)
}

// TestLoginVerifyOTP_FailedIssuance_DoesNotConsumeChallenge_RetrySucceeds
// covers requirement 8, generalized beyond notification-service: if
// issueSession fails for *any* reason after a valid OTP has already been
// verified, the login challenge must not be left permanently consumed -
// otherwise a legitimate retry comes back "invalid or expired login
// challenge", indistinguishable from a genuinely expired session, even
// though the original attempt was entirely valid.
func TestLoginVerifyOTP_FailedIssuance_DoesNotConsumeChallenge_RetrySucceeds(t *testing.T) {
	svc, _, sessions := newTestServiceWithCleanup(newFakeSessionCleaner(nil))

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

	// SetupVerifyOTP's code above already consumed this TOTP period's
	// anti-replay counter, so the failed attempt below needs a code from a
	// later period - wait for one, the same way a real user's
	// authenticator app rolling over to a new code would.
	waitForNextTOTPPeriod(t)

	// Inject a one-shot failure into an issueSession dependency that has
	// nothing to do with notification-service, to prove the fix is about
	// ordering (finalize only after success), not specifically about the
	// cleanup call.
	sessions.failNextActivate(errors.New("redis: connection refused"))

	firstCode := genCode(t, setup.Secret)
	if _, err := svc.LoginVerifyOTP(context.Background(), login.ChallengeToken, firstCode); err == nil {
		t.Fatal("LoginVerifyOTP: want an error from the injected issueSession failure, got nil")
	}

	// A real retry needs a code from a later time-step than the one just
	// consumed above by verifyOTP (which ran, and succeeded, before the
	// injected fault was ever reached). Wait for the next TOTP period so
	// genCode produces one, same as above.
	waitForNextTOTPPeriod(t)

	// Retry with the SAME challenge token and this fresh valid OTP. Before
	// the fix, this would fail with ErrChallengeInvalid because Consume
	// had already run on the failed first attempt.
	retryCode := genCode(t, setup.Secret)
	session, err := svc.LoginVerifyOTP(context.Background(), login.ChallengeToken, retryCode)
	if err != nil {
		t.Fatalf("retry LoginVerifyOTP after issueSession failure: got %v, want success (challenge must survive an unrelated issuance failure)", err)
	}
	if session.AccessToken == "" {
		t.Error("retry LoginVerifyOTP did not issue a full session")
	}
}

// TestLoginVerifyOTP_EndToEnd_PreviousSessionExists_NotificationServiceUnavailable
// is the full behavioral regression test for the originally reported bug:
// a previous (not explicitly logged-out) session exists, notification-
// service is unavailable, and the user logs in again with a fully valid
// TOTP code. This must succeed on the first attempt - no intermediate
// 500, and therefore nothing that could turn into a misleading "expired
// session" on a retry that should never have been necessary.
func TestLoginVerifyOTP_EndToEnd_PreviousSessionExists_NotificationServiceUnavailable(t *testing.T) {
	cleaner := newFakeSessionCleaner(errNotificationServiceUnavailable)
	svc, _, _ := newTestServiceWithCleanup(cleaner)

	setup, err := svc.Register(context.Background(), appauth.RegisterInput{Email: "bee@example.com", Password: "supersecret"})
	if err != nil {
		t.Fatalf("Register: %v", err)
	}
	if _, err := svc.SetupVerifyOTP(context.Background(), setup.SetupToken, genCode(t, setup.Secret)); err != nil {
		t.Fatalf("SetupVerifyOTP (establishes the previous session): %v", err)
	}

	// Simulates the access token expiring without an explicit logout: the
	// previous session is never deactivated, so the next login's
	// issueSession will see hadPrevious=true.
	login, err := svc.Login(context.Background(), appauth.LoginInput{Email: "bee@example.com", Password: "supersecret"})
	if err != nil {
		t.Fatalf("Login: %v", err)
	}

	session, err := svc.LoginVerifyOTP(context.Background(), login.ChallengeToken, genNextCode(t, setup.Secret))
	if err != nil {
		t.Fatalf("first LoginVerifyOTP attempt: got error %v, want immediate success (no intermediate 500)", err)
	}
	if session.AccessToken == "" || session.RefreshToken == "" {
		t.Fatal("LoginVerifyOTP did not return valid new authentication tokens")
	}

	// The challenge is correctly single-use after a genuine success - this
	// is expected, correct behavior (not the bug): replaying it must still
	// fail, but with the ordinary "already used" outcome, not as a
	// consequence of a spurious earlier failure.
	if _, err := svc.LoginVerifyOTP(context.Background(), login.ChallengeToken, genCodeAt(t, setup.Secret, time.Now().UTC().Add(60*time.Second))); !errors.Is(err, appauth.ErrChallengeInvalid) {
		t.Fatalf("replaying the already-used challenge: got %v, want ErrChallengeInvalid", err)
	}

	cleaner.waitForCall(t)
}
