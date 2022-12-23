-- This file should undo anything in `up.sql`

ALTER TABLE notes
DROP COLUMN delete_after_read,
DROP COLUMN allow_delete_with_passphrase;
