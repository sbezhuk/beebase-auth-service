CREATE TABLE users (
    id            UUID PRIMARY KEY,
    -- Application normalizes email to lowercase/trimmed before writing,
    -- so a plain uniqueness constraint is enough without a citext extension.
    email         TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);
