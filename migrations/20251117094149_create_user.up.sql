-- Add up migration script here
CREATE TABLE users (
    id text PRIMARY KEY,
    email text UNIQUE NOT NULL,
    password_hash text NOT NULL,
    first_name text NOT NULL,
    last_name text NOT NULL,
    role text NOT NULL CHECK (role IN ('applicant','officer','admin')),
    created_at timestamptz DEFAULT now()
);
