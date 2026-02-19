-- +goose Up
CREATE TABLE IF NOT EXISTS login_attempts (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    email VARCHAR(255) NOT NULL,
    ip_address VARCHAR(45) NOT NULL,
    user_agent TEXT,
    attempt_time TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    success BOOLEAN NOT NULL DEFAULT FALSE,
    failure_reason VARCHAR(100),
    device_fingerprint VARCHAR(255),
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL
);

-- Indexes for efficient lookups
CREATE INDEX idx_login_attempts_email_time ON login_attempts(email, attempt_time DESC);
CREATE INDEX idx_login_attempts_ip_time ON login_attempts(ip_address, attempt_time DESC);
CREATE INDEX idx_login_attempts_expires_at ON login_attempts(expires_at);
CREATE INDEX idx_login_attempts_email_success_time ON login_attempts(email, success, attempt_time DESC);
CREATE INDEX idx_login_attempts_device_fingerprint_time ON login_attempts(device_fingerprint, attempt_time DESC);

COMMENT ON TABLE login_attempts IS 'Track login attempts for rate limiting and audit purposes';
COMMENT ON COLUMN login_attempts.device_fingerprint IS 'Hash of IP + User-Agent for device-based rate limiting';
COMMENT ON COLUMN login_attempts.expires_at IS 'TTL for automatic cleanup of old records';

-- +goose Down
DROP INDEX IF EXISTS idx_login_attempts_device_fingerprint_time;
DROP INDEX IF EXISTS idx_login_attempts_email_success_time;
DROP INDEX IF EXISTS idx_login_attempts_expires_at;
DROP INDEX IF EXISTS idx_login_attempts_ip_time;
DROP INDEX IF EXISTS idx_login_attempts_email_time;
DROP TABLE IF EXISTS login_attempts;
