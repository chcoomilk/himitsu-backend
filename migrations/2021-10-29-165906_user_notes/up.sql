-- Your SQL goes here
CREATE TABLE user_notes (
    id VARCHAR UNIQUE PRIMARY KEY,
    note_id SERIAL REFERENCES notes(id),
    user_id SERIAL REFERENCES users(id),
    created_at TIMESTAMP NOT NULL DEFAULT now()
);
