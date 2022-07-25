-- Your SQL goes here

CREATE TABLE notes (
  id VARCHAR(32) UNIQUE PRIMARY KEY,
  title VARCHAR NOT NULL,
  content BYTEA NOT NULL,
  discoverable BOOLEAN NOT NULL,
  frontend_encryption BOOLEAN NOT NULL,
  backend_encryption BOOLEAN NOT NULL,
  created_at TIMESTAMP NOT NULL DEFAULT now(),
  expires_at TIMESTAMP
);
