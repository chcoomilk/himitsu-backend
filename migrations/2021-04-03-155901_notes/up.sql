-- Your SQL goes here

CREATE TABLE notes (
  id SERIAL PRIMARY KEY,
  title VARCHAR NOT NULL,
  content VARCHAR NOT NULL,
  password VARCHAR NOT NULL,
  created_at TIMESTAMP NOT NULL,
  expired_at TIMESTAMP NOT NULL
);
