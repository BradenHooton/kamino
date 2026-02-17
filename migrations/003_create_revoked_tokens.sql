-- +goose Up
CREATE TABLE IF NOT EXISTS revoked_tokens (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    jti VARCHAR(255) NOT NULL UNIQUE,
    user_id UUID NOT NULL,
    token_type VARCHAR(20) NOT NULL,
    revoked_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    reason VARCHAR(255),
    CONSTRAINT fk_revoked_tokens_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE INDEX idx_revoked_tokens_jti ON revoked_tokens(jti);
CREATE INDEX idx_revoked_tokens_expires_at ON revoked_tokens(expires_at);
CREATE INDEX idx_revoked_tokens_user_id ON revoked_tokens(user_id);

COMMENT ON TABLE revoked_tokens IS 'JWT token revocation blacklist for logout and security events';
COMMENT ON COLUMN revoked_tokens.jti IS 'JWT ID claim - unique identifier for each token';
COMMENT ON COLUMN revoked_tokens.expires_at IS 'Original token expiry for automatic cleanup';

-- +goose Down
DROP INDEX IF EXISTS idx_revoked_tokens_user_id;
DROP INDEX IF EXISTS idx_revoked_tokens_expires_at;
DROP INDEX IF EXISTS idx_revoked_tokens_jti;
DROP TABLE IF EXISTS revoked_tokens;
