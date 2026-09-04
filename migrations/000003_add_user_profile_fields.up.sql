-- Profile fields: display name and an optional avatar. avatar_media_id
-- references a file in media-service (a different database entirely), so
-- it's a plain UUID column, not a foreign key - ownership is verified
-- against media-service itself before this column is ever written.
ALTER TABLE users
    ADD COLUMN first_name TEXT NOT NULL DEFAULT '',
    ADD COLUMN last_name TEXT NOT NULL DEFAULT '',
    ADD COLUMN avatar_media_id UUID;
