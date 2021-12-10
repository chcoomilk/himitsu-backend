-- This file should undo anything in `up.sql`

DROP TYPE IF EXISTS encryption_origin;

ALTER TABLE notes
ALTER COLUMN password SET NOT NULL,
ALTER COLUMN expired_at SET NOT NULL,
DROP COLUMN encryption,
DROP COLUMN does_expire,
DROP COLUMN updated_at;
