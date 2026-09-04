-- One row per user, created the moment TOTP setup begins (at registration,
-- or when an existing user without an enabled credential logs in). The
-- primary key is user_id directly rather than a synthetic id: this is a
-- genuine 1:1 relationship with users, unlike refresh_tokens/login_challenges
-- which are 1:many.
CREATE TABLE two_factor_credentials (
    user_id                 UUID PRIMARY KEY REFERENCES users (id) ON DELETE CASCADE,
    -- AES-256-GCM ciphertext of the TOTP secret (nonce prepended); the key
    -- is TOTP_ENCRYPTION_KEY, held only in server config. Never stored or
    -- logged in plaintext.
    secret_encrypted        BYTEA NOT NULL,
    -- NULL until the first successful setup-verify; a NULL here means the
    -- account cannot log in yet (2FA setup incomplete).
    enabled_at              TIMESTAMPTZ,
    -- SHA-256 hex digest of the opaque setup token handed to the client
    -- during registration/login-triggered setup. NULL once no setup is
    -- pending (i.e. once enabled_at is set and never regenerated).
    setup_token_hash        TEXT UNIQUE,
    setup_token_expires_at  TIMESTAMPTZ,
    failed_attempts         INT NOT NULL DEFAULT 0,
    locked_until            TIMESTAMPTZ,
    created_at              TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at              TIMESTAMPTZ NOT NULL DEFAULT now()
);
