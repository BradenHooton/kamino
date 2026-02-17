-- +goose Up
-- Create a partial index for efficient cleanup of expired tokens
-- This index only includes tokens with expires_at in the past,
-- making the cleanup query (DELETE FROM revoked_tokens WHERE expires_at < NOW())
-- much more efficient
CREATE INDEX idx_revoked_tokens_cleanup ON revoked_tokens(expires_at)
WHERE expires_at < CURRENT_TIMESTAMP;

-- +goose Down
DROP INDEX IF EXISTS idx_revoked_tokens_cleanup;
