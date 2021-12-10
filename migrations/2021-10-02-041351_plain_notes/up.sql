-- Your SQL goes here

CREATE TABLE plain_notes (
  id VARCHAR PRIMARY KEY,
  title VARCHAR NOT NULL,
  content VARCHAR NOT NULL,
  is_encrypted BOOLEAN NOT NULL,
  created_at TIMESTAMP NOT NULL,
  expired_at TIMESTAMP NOT NULL
);
