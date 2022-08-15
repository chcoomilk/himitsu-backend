-- This file should undo anything in `up.sql`

ALTER TABLE notes ALTER COLUMN title ADD NOT NULL;
