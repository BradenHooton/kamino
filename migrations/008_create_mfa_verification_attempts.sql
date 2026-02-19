-- +goose Up
CREATE TABLE IF NOT EXISTS mfa_verification_attempts (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL,
    device_fingerprint VARCHAR(255) NOT NULL,
    ip_address INET NOT NULL,
    success BOOLEAN NOT NULL,
    failure_reason VARCHAR(255),
    attempted_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT fk_mfa_attempt_user
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    CONSTRAINT ck_failure_reason_on_failure
        CHECK (success = true OR failure_reason IS NOT NULL)
);

-- Indexes for rate limiting queries
CREATE INDEX idx_mfa_attempt_user_time ON mfa_verification_attempts(user_id, attempted_at DESC);
CREATE INDEX idx_mfa_attempt_device_time ON mfa_verification_attempts(device_fingerprint, attempted_at DESC);
CREATE INDEX idx_mfa_attempt_ip_time ON mfa_verification_attempts(ip_address, attempted_at DESC);

-- Index for cleanup (delete attempts older than 30 days)
CREATE INDEX idx_mfa_attempt_cleanup ON mfa_verification_attempts(attempted_at)
    WHERE attempted_at < NOW() - INTERVAL '30 days';

-- Comments
COMMENT ON TABLE mfa_verification_attempts IS 'Track MFA verification attempts for rate limiting and security monitoring';
COMMENT ON COLUMN mfa_verification_attempts.device_fingerprint IS 'Hash of user agent for device-based rate limiting';
COMMENT ON COLUMN mfa_verification_attempts.failure_reason IS 'Reason for failed verification: invalid_code, expired, replay, rate_limited, etc.';

-- +goose Down
DROP INDEX IF EXISTS idx_mfa_attempt_cleanup;
DROP INDEX IF EXISTS idx_mfa_attempt_ip_time;
DROP INDEX IF EXISTS idx_mfa_attempt_device_time;
DROP INDEX IF EXISTS idx_mfa_attempt_user_time;
DROP TABLE IF EXISTS mfa_verification_attempts;
