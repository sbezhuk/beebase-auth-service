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

// TestValidate_RejectsCodeFromTwoPeriodsAgo pins down the boundary of the
// documented skew tolerance (one period, 30s, either side): a code that's
// genuinely expired - not just a moment past its own window - must never
// validate. See BEEB-41.
func TestValidate_RejectsCodeFromTwoPeriodsAgo(t *testing.T) {
	secret := genSecret(t)
	now := time.Now().UTC()
	expired := codeAt(t, secret, now.Add(-90*time.Second))

	if totp.Validate(expired, secret) {
		t.Fatal("Validate accepted a code from two periods ago")
	}
}

// TestValidate_AcceptsCodeFromPreviousPeriod documents the intended skew
// tolerance itself (distinct from replay): a code just past its own 30s
// window still validates once, to tolerate ordinary clock drift/latency.
func TestValidate_AcceptsCodeFromPreviousPeriod(t *testing.T) {
	secret := genSecret(t)
	now := time.Now().UTC()
	justExpired := codeAt(t, secret, now.Add(-30*time.Second))

	if !totp.Validate(justExpired, secret) {
		t.Fatal("Validate rejected a code still inside the documented skew window")
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
