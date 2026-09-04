-- Secure temporary state for the forgot-password flow: email submitted ->
-- OTP verified -> password reset. user_id is nullable and NULL whenever the
-- request was ineligible (unknown email, or the account has no enabled 2FA
-- credential) - a real row is created either way so verify-otp has
-- something to look up and fails identically in both cases, never leaking
-- which one it was.
CREATE TABLE password_reset_flows (
    id                      UUID PRIMARY KEY,
    user_id                 UUID REFERENCES users (id) ON DELETE CASCADE,
    -- SHA-256 hex digest of the opaque flow token returned by
    -- password-reset/request. Never the raw token.
    flow_token_hash         TEXT NOT NULL UNIQUE,
    otp_verified_at         TIMESTAMPTZ,
    -- Attempt cap scoped to this flow alone, deliberately independent of
    -- two_factor_credentials.failed_attempts: an attacker guessing against
    -- a reset flow (which requires no password) must never be able to lock
    -- the real account out of logging in.
    otp_attempts            INT NOT NULL DEFAULT 0,
    -- SHA-256 hex digest of the single-use reset token issued once the OTP
    -- step succeeds; NULL until then. confirm requires this to be set.
    reset_token_hash        TEXT UNIQUE,
    reset_token_expires_at  TIMESTAMPTZ,
    expires_at              TIMESTAMPTZ NOT NULL,
    consumed_at             TIMESTAMPTZ,
    created_at              TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_password_reset_flows_user_id ON password_reset_flows (user_id);
