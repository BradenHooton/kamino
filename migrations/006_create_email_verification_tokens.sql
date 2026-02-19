-- +goose Up
CREATE TABLE IF NOT EXISTS email_verification_tokens (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL,
    token_hash VARCHAR(255) NOT NULL,
    email VARCHAR(255) NOT NULL,
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    used_at TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT fk_email_verification_user
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

-- Indexes
CREATE INDEX idx_email_verification_user_id ON email_verification_tokens(user_id);
CREATE INDEX idx_email_verification_expires_at ON email_verification_tokens(expires_at);
CREATE INDEX idx_email_verification_pending ON email_verification_tokens(email, used_at)
    WHERE used_at IS NULL AND expires_at > NOW();

-- Comments
COMMENT ON TABLE email_verification_tokens IS 'Email verification tokens for user registration';
COMMENT ON COLUMN email_verification_tokens.token_hash IS 'Bcrypt hash of verification token (never store plain token)';
COMMENT ON COLUMN email_verification_tokens.expires_at IS 'Token expiry timestamp (24 hours from creation)';
COMMENT ON COLUMN email_verification_tokens.used_at IS 'Timestamp when token was used (prevents reuse)';

-- +goose Down
DROP INDEX IF EXISTS idx_email_verification_pending;
DROP INDEX IF EXISTS idx_email_verification_expires_at;
DROP INDEX IF EXISTS idx_email_verification_user_id;
DROP TABLE IF EXISTS email_verification_tokens;
