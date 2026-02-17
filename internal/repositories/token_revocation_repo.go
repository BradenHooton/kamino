package repositories

import (
	"context"
	"time"

	"github.com/BradenHooton/kamino/internal/database"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

type TokenRevocationRepository struct {
	pool *pgxpool.Pool
}

func NewTokenRevocationRepository(db *database.DB) *TokenRevocationRepository {
	return &TokenRevocationRepository{pool: db.Pool}
}

// RevokeToken adds a token to the revocation blacklist
func (r *TokenRevocationRepository) RevokeToken(ctx context.Context, jti, userID, tokenType string, expiresAt time.Time, reason string) error {
	query := `
		INSERT INTO revoked_tokens (id, jti, user_id, token_type, expires_at, reason)
		VALUES ($1, $2, $3, $4, $5, $6)
	`

	id := uuid.New().String()
	_, err := r.pool.Exec(ctx, query, id, jti, userID, tokenType, expiresAt, reason)

	if err != nil {
		return database.MapPostgresError(err)
	}

	return nil
}

// IsTokenRevoked checks if a token is in the revocation blacklist
func (r *TokenRevocationRepository) IsTokenRevoked(ctx context.Context, jti string) (bool, error) {
	query := `SELECT EXISTS(SELECT 1 FROM revoked_tokens WHERE jti = $1)`

	var exists bool
	err := r.pool.QueryRow(ctx, query, jti).Scan(&exists)

	if err != nil {
		return false, database.MapPostgresError(err)
	}

	return exists, nil
}

// RevokeAllUserTokens creates an audit log entry for logout-all events
// Actual token revocation happens via TokenKey rotation in User.Update()
func (r *TokenRevocationRepository) RevokeAllUserTokens(ctx context.Context, userID, reason string) error {
	// Insert audit trail record
	query := `
		INSERT INTO revoked_tokens (id, jti, user_id, token_type, expires_at, reason)
		VALUES (gen_random_uuid(), 'logout-all-' || $1 || '-' || $2::text, $1, 'all',
				NOW() + INTERVAL '1 hour', $3)
	`

	_, err := r.pool.Exec(ctx, query, userID, time.Now().Unix(), reason)
	return database.MapPostgresError(err)
}

// CleanupExpiredTokens removes expired revoked tokens (call periodically)
func (r *TokenRevocationRepository) CleanupExpiredTokens(ctx context.Context) (int64, error) {
	query := `DELETE FROM revoked_tokens WHERE expires_at < $1`

	result, err := r.pool.Exec(ctx, query, time.Now())
	if err != nil {
		return 0, database.MapPostgresError(err)
	}

	return result.RowsAffected(), nil
}
