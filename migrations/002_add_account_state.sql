-- +goose Up
ALTER TABLE users
    ADD COLUMN status VARCHAR(20) NOT NULL DEFAULT 'active',
    ADD COLUMN locked_until TIMESTAMP WITH TIME ZONE,
    ADD COLUMN password_changed_at TIMESTAMP WITH TIME ZONE;

CREATE INDEX idx_users_status ON users(status);

COMMENT ON COLUMN users.status IS 'Account status: active, suspended, disabled';
COMMENT ON COLUMN users.locked_until IS 'Temporary account lock expiration time';
COMMENT ON COLUMN users.password_changed_at IS 'Last password change timestamp for token invalidation';

-- +goose Down
DROP INDEX IF EXISTS idx_users_status;
ALTER TABLE users
    DROP COLUMN IF EXISTS password_changed_at,
    DROP COLUMN IF EXISTS locked_until,
    DROP COLUMN IF EXISTS status;
