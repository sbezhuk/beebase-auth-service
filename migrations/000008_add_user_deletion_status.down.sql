DROP INDEX IF EXISTS users_deletion_status_idx;
ALTER TABLE users DROP COLUMN IF EXISTS deletion_status;
