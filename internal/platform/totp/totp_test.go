package totp_test

import (
	"testing"
	"time"

	pquernatotp "github.com/pquerna/otp/totp"

	"github.com/sbezhuk/beebase-auth-service/internal/platform/totp"
)

func genSecret(t *testing.T) string {
	t.Helper()
	secret, _, err := totp.GenerateSecret("BeeBase Test", "bee@example.com")
	if err != nil {
		t.Fatalf("GenerateSecret: %v", err)
	}
	return secret
}

func codeAt(t *testing.T, secret string, at time.Time) string {
	t.Helper()
	code, err := pquernatotp.GenerateCode(secret, at)
	if err != nil {
		t.Fatalf("GenerateCode: %v", err)
	}
	return code
}

// TestValidate_RejectsCodeFromPreviousPeriod is the regression test for
// BEEB-41: once the server's clock moves into a new 30s period, a code
// from the period that just ended must stop validating immediately - not
// linger for one more period. now.Add(-30s) always lands exactly one
// period-counter behind now, regardless of where "now" falls within its
// own window (subtracting one full period always decrements the floored
// counter by exactly one).
func TestValidate_RejectsCodeFromPreviousPeriod(t *testing.T) {
	secret := genSecret(t)
	now := time.Now().UTC()
	justExpired := codeAt(t, secret, now.Add(-30*time.Second))

	if totp.Validate(justExpired, secret) {
		t.Fatal("Validate accepted a code from the period that just ended")
	}
}

// TestValidate_RejectsCodeFromTwoPeriodsAgo confirms a code well outside
// its validity period is (still, obviously) rejected.
func TestValidate_RejectsCodeFromTwoPeriodsAgo(t *testing.T) {
	secret := genSecret(t)
	now := time.Now().UTC()
	expired := codeAt(t, secret, now.Add(-90*time.Second))

	if totp.Validate(expired, secret) {
		t.Fatal("Validate accepted a code from two periods ago")
	}
}

// TestValidate_AcceptsCodeFromNextPeriod documents the one remaining,
// deliberately one-sided tolerance: a code for the period immediately
// after the current one still validates, for an authenticator whose clock
// runs slightly fast. This is not what BEEB-41 was about - only a code
// arriving late (from a period already over) was ever the bug.
func TestValidate_AcceptsCodeFromNextPeriod(t *testing.T) {
	secret := genSecret(t)
	now := time.Now().UTC()
	early := codeAt(t, secret, now.Add(30*time.Second))

	if !totp.Validate(early, secret) {
		t.Fatal("Validate rejected a code for the immediately-following period")
	}
}

// TestValidateAt_MatchedCounterIsMonotonicWithTime confirms ValidateAt
// reports a strictly greater counter for a code from a later period, which
// is what callers rely on (domain/totp.Credential.IsCodeConsumed) to reject
// replay of an already-used code without also rejecting a legitimately
// later one.
func TestValidateAt_MatchedCounterIsMonotonicWithTime(t *testing.T) {
	secret := genSecret(t)
	now := time.Now().UTC()

	code1 := codeAt(t, secret, now)
	ok1, counter1 := totp.ValidateAt(code1, secret, now)
	if !ok1 {
		t.Fatal("ValidateAt rejected the current code")
	}

	code2 := codeAt(t, secret, now.Add(30*time.Second))
	ok2, counter2 := totp.ValidateAt(code2, secret, now)
	if !ok2 {
		t.Fatal("ValidateAt rejected the next period's code under forward skew")
	}

	if counter2 <= counter1 {
		t.Fatalf("matched counters not increasing: counter1=%d counter2=%d", counter1, counter2)
	}
}

func TestValidate_RejectsWrongCode(t *testing.T) {
	secret := genSecret(t)
	if totp.Validate("000000", secret) {
		t.Fatal("Validate accepted an arbitrary wrong code")
	}
}
