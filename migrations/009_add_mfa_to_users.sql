-- +goose Up
ALTER TABLE users
    ADD COLUMN mfa_enabled BOOLEAN NOT NULL DEFAULT FALSE,
    ADD COLUMN mfa_enrolled_at TIMESTAMP WITH TIME ZONE;

-- Index for querying MFA-enabled users
CREATE INDEX idx_users_mfa_enabled ON users(mfa_enabled)
    WHERE mfa_enabled = TRUE;

-- Comments
COMMENT ON COLUMN users.mfa_enabled IS 'Whether MFA is currently enabled for this user';
COMMENT ON COLUMN users.mfa_enrolled_at IS 'When user first successfully enrolled in MFA';

-- +goose Down
DROP INDEX IF EXISTS idx_users_mfa_enabled;
ALTER TABLE users
    DROP COLUMN mfa_enrolled_at,
    DROP COLUMN mfa_enabled;
