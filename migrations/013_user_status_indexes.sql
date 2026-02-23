-- +goose Up
-- Composite index for status-filtered admin queries (e.g., list suspended users sorted by created_at)
CREATE INDEX IF NOT EXISTS idx_users_status_created ON users(status, created_at DESC);

-- Partial index for active lock checks (locked_until IS NOT NULL keeps it small)
CREATE INDEX IF NOT EXISTS idx_users_locked ON users(locked_until)
    WHERE locked_until IS NOT NULL;

-- +goose Down
DROP INDEX IF EXISTS idx_users_locked;
DROP INDEX IF EXISTS idx_users_status_created;
