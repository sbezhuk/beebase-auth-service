-- The OTP-required gate between a successful password check and full
-- session issuance. A login attempt for a 2FA-enabled account creates one
-- of these instead of a session; verify-otp trades a valid challenge (plus
-- a correct OTP) for a real session.
CREATE TABLE login_challenges (
    id          UUID PRIMARY KEY,
    user_id     UUID NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    -- SHA-256 hex digest of the opaque challenge token handed to the
    -- client; the raw token itself is never persisted.
    token_hash  TEXT NOT NULL UNIQUE,
    expires_at  TIMESTAMPTZ NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    consumed_at TIMESTAMPTZ
);

CREATE INDEX idx_login_challenges_user_id ON login_challenges (user_id);
