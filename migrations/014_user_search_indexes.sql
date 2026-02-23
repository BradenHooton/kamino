-- +goose Up
-- Enable trigram extension for ILIKE-based text search on email and name
CREATE EXTENSION IF NOT EXISTS pg_trgm;

-- GIN indexes for fast trigram ILIKE queries on email and name
CREATE INDEX IF NOT EXISTS idx_users_email_trgm ON users USING gin(email gin_trgm_ops);
CREATE INDEX IF NOT EXISTS idx_users_name_trgm  ON users USING gin(name  gin_trgm_ops);

-- Composite index for status + role filtered listing (used by both search and dashboard)
CREATE INDEX IF NOT EXISTS idx_users_status_role ON users(status, role, created_at DESC);

-- +goose Down
DROP INDEX IF EXISTS idx_users_status_role;
DROP INDEX IF EXISTS idx_users_name_trgm;
DROP INDEX IF EXISTS idx_users_email_trgm;
-- Note: pg_trgm extension is intentionally not dropped (may be used by other tables)
