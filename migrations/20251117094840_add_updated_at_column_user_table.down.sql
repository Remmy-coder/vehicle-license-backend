-- Add down migration script here
DROP TRIGGER IF EXISTS set_timestamp ON users;
DROP FUNCTION IF EXISTS update_timestamp();
ALTER TABLE users DROP COLUMN IF EXISTS updated_at;

