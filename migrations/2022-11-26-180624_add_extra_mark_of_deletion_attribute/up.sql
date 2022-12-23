-- Your SQL goes here

ALTER TABLE notes
ADD delete_after_read INT,
ADD allow_delete_with_passphrase boolean NOT NULL DEFAULT false;
