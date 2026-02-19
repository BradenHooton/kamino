-- +goose Up
CREATE TABLE IF NOT EXISTS mfa_devices (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL,
    device_name VARCHAR(255) NOT NULL,
    totp_secret_encrypted BYTEA NOT NULL,
    totp_secret_nonce BYTEA NOT NULL,
    backup_codes JSONB NOT NULL DEFAULT '[]'::jsonb,
    last_used_at TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    verified_at TIMESTAMP WITH TIME ZONE,

    CONSTRAINT fk_mfa_device_user
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    CONSTRAINT ck_device_name_not_empty
        CHECK (device_name != '')
);

-- Indexes
CREATE INDEX idx_mfa_device_user_id ON mfa_devices(user_id);
CREATE INDEX idx_mfa_device_verified ON mfa_devices(user_id, verified_at)
    WHERE verified_at IS NOT NULL;

-- Comments
COMMENT ON TABLE mfa_devices IS 'MFA devices storing encrypted TOTP secrets per user';
COMMENT ON COLUMN mfa_devices.totp_secret_encrypted IS 'AES-256-GCM encrypted TOTP secret (32 bytes)';
COMMENT ON COLUMN mfa_devices.totp_secret_nonce IS 'GCM nonce for decryption (12 bytes)';
COMMENT ON COLUMN mfa_devices.backup_codes IS 'JSON array of bcrypt-hashed backup codes with metadata';
COMMENT ON COLUMN mfa_devices.last_used_at IS 'Timestamp of last successful TOTP verification (for replay prevention)';
COMMENT ON COLUMN mfa_devices.verified_at IS 'When device was first verified with TOTP code';

-- +goose Down
DROP INDEX IF EXISTS idx_mfa_device_verified;
DROP INDEX IF EXISTS idx_mfa_device_user_id;
DROP TABLE IF EXISTS mfa_devices;
