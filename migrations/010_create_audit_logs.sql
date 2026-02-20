-- +goose Up
CREATE TABLE IF NOT EXISTS audit_logs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    event_type VARCHAR(50) NOT NULL,         -- "login", "logout", "role_change", etc.
    actor_id UUID,                           -- User who performed action
    target_id UUID,                          -- User affected by action
    resource_type VARCHAR(50),               -- "user", "api_key", "permission"
    resource_id VARCHAR(255),
    action VARCHAR(50) NOT NULL,             -- "create", "update", "delete", "access"
    success BOOLEAN NOT NULL DEFAULT true,
    failure_reason TEXT,
    ip_address INET,
    user_agent TEXT,
    metadata JSONB,                          -- Additional context
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT fk_audit_actor FOREIGN KEY (actor_id) REFERENCES users(id) ON DELETE SET NULL,
    CONSTRAINT fk_audit_target FOREIGN KEY (target_id) REFERENCES users(id) ON DELETE SET NULL
);

CREATE INDEX idx_audit_logs_event_type ON audit_logs(event_type);
CREATE INDEX idx_audit_logs_actor_id ON audit_logs(actor_id);
CREATE INDEX idx_audit_logs_created_at ON audit_logs(created_at DESC);
CREATE INDEX idx_audit_logs_success ON audit_logs(success) WHERE success = false;

-- +goose Down
DROP INDEX IF EXISTS idx_audit_logs_success;
DROP INDEX IF EXISTS idx_audit_logs_created_at;
DROP INDEX IF EXISTS idx_audit_logs_actor_id;
DROP INDEX IF EXISTS idx_audit_logs_event_type;
DROP TABLE IF EXISTS audit_logs;
