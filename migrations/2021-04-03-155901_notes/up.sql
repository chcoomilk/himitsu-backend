-- Your SQL goes here

CREATE TABLE notes (
  id SERIAL PRIMARY KEY,
  title VARCHAR NOT NULL,
  content BYTEA NOT NULL,
  frontend_encryption BOOLEAN NOT NULL,
  backend_encryption BOOLEAN NOT NULL,
  updated_at TIMESTAMP NOT NULL DEFAULT now(),
  created_at TIMESTAMP NOT NULL DEFAULT now(),
  expired_at TIMESTAMP
);
