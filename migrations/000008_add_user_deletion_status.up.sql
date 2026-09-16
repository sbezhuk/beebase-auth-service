ALTER TABLE users
    ADD COLUMN deletion_status TEXT NOT NULL DEFAULT 'active'
    CHECK (deletion_status IN ('active', 'deletion_pending'));

CREATE INDEX users_deletion_status_idx ON users (deletion_status);
