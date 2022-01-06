-- Your SQL goes here

ALTER TABLE notes
ADD COLUMN encryption BOOLEAN NOT NULL DEFAULT false,
ADD COLUMN updated_at TIMESTAMP NOT NULL DEFAULT now(),
ALTER COLUMN expired_at DROP NOT NULL,
ALTER COLUMN password DROP NOT NULL;

DROP TABLE plain_notes;

-- CREATE TYPE encryption_origin AS ENUM ('no encryption', 'frontend', 'backend');

-- ALTER TABLE notes
-- ADD COLUMN encryption encryption_origin;
-- seems not yet possible to implement in diesel
