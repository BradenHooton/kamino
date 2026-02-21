-- +goose Up
-- Create mfa_recovery_requests table for MFA recovery workflow
CREATE TABLE mfa_recovery_requests (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    initiator_admin_id UUID NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    confirmer_admin_id UUID,
    reason TEXT NOT NULL,
    status VARCHAR(20) NOT NULL DEFAULT 'pending',
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    confirmed_at TIMESTAMP,
    expires_at TIMESTAMP NOT NULL,
    executed_at TIMESTAMP,

    CONSTRAINT status_valid CHECK (status IN ('pending', 'confirmed', 'executed', 'expired', 'cancelled')),
    CONSTRAINT reason_length CHECK (length(reason) >= 10),
    CONSTRAINT confirmer_different FROM initiator CHECK (confirmer_admin_id IS NULL OR confirmer_admin_id != initiator_admin_id)
);

-- Index for finding requests by user
CREATE INDEX idx_mfa_recovery_user_id ON mfa_recovery_requests(user_id);

-- Index for finding pending requests
CREATE INDEX idx_mfa_recovery_status ON mfa_recovery_requests(status);

-- Index for cleanup (find expired requests)
CREATE INDEX idx_mfa_recovery_expires_at ON mfa_recovery_requests(expires_at);

-- +goose Down
DROP TABLE mfa_recovery_requests;
