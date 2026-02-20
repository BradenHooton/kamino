package repositories

import (
	"context"
	"fmt"
	"time"

	"github.com/BradenHooton/kamino/internal/auth"
	"github.com/BradenHooton/kamino/internal/database"
	"github.com/BradenHooton/kamino/internal/models"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/lib/pq"
)

// APIKeyRepositoryImpl implements APIKeyRepository
type APIKeyRepositoryImpl struct {
	pool *pgxpool.Pool
}

// NewAPIKeyRepository creates a new API key repository
func NewAPIKeyRepository(db *database.DB) APIKeyRepository {
	return &APIKeyRepositoryImpl{pool: db.Pool}
}

// scanAPIKeyRow handles nullable fields and populates an APIKey model from a database row
func scanAPIKeyRow(scanner interface {
	Scan(dest ...interface{}) error
}) (*models.APIKey, error) {
	var apiKey models.APIKey
	var lastUsedAt, expiresAt, revokedAt *time.Time

	err := scanner.Scan(
		&apiKey.ID,
		&apiKey.UserID,
		&apiKey.KeyHash,
		&apiKey.KeyPrefix,
		&apiKey.Name,
		pq.Array(&apiKey.Scopes),
		&lastUsedAt,
		&expiresAt,
		&revokedAt,
		&apiKey.CreatedAt,
		&apiKey.UpdatedAt,
	)
	if err != nil {
		return nil, database.MapPostgresError(err)
	}

	apiKey.LastUsedAt = lastUsedAt
	apiKey.ExpiresAt = expiresAt
	apiKey.RevokedAt = revokedAt

	return &apiKey, nil
}

// scanAPIKeyRows iterates through rows and scans each into APIKey models
func scanAPIKeyRows(rows pgx.Rows) ([]*models.APIKey, error) {
	defer rows.Close()

	apiKeys := make([]*models.APIKey, 0)

	for rows.Next() {
		apiKey, err := scanAPIKeyRow(rows)
		if err != nil {
			return nil, fmt.Errorf("failed to scan api key: %w", err)
		}
		apiKeys = append(apiKeys, apiKey)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating rows: %w", err)
	}

	return apiKeys, nil
}

// Create stores a new API key in the database
func (r *APIKeyRepositoryImpl) Create(ctx context.Context, apiKey *models.APIKey) error {
	query := `
		INSERT INTO api_keys (id, user_id, key_hash, key_prefix, name, scopes, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
	`

	err := r.pool.QueryRow(ctx, query,
		apiKey.ID,
		apiKey.UserID,
		apiKey.KeyHash,
		apiKey.KeyPrefix,
		apiKey.Name,
		pq.Array(apiKey.Scopes),
		apiKey.CreatedAt,
		apiKey.UpdatedAt,
	).Scan()

	if err != nil && err != pgx.ErrNoRows {
		return database.MapPostgresError(err)
	}

	return nil
}

// GetByHash retrieves an active API key by its hash (constant-time comparison)
func (r *APIKeyRepositoryImpl) GetByHash(ctx context.Context, keyHash string) (*models.APIKey, error) {
	query := `
		SELECT id, user_id, key_hash, key_prefix, name, scopes, last_used_at, expires_at, revoked_at, created_at, updated_at
		FROM api_keys
		WHERE key_hash = $1 AND revoked_at IS NULL
		LIMIT 1
	`

	apiKey, err := scanAPIKeyRow(r.pool.QueryRow(ctx, query, keyHash))
	if err != nil {
		return nil, err
	}

	// Verify hash with constant-time comparison as defense-in-depth
	if !auth.ConstantTimeHashCompare(apiKey.KeyHash, keyHash) {
		return nil, models.ErrNotFound
	}

	// Check if expired
	if apiKey.IsExpired() {
		return nil, models.ErrNotFound
	}

	return apiKey, nil
}

// GetByID retrieves an API key by its ID
func (r *APIKeyRepositoryImpl) GetByID(ctx context.Context, id string) (*models.APIKey, error) {
	query := `
		SELECT id, user_id, key_hash, key_prefix, name, scopes, last_used_at, expires_at, revoked_at, created_at, updated_at
		FROM api_keys
		WHERE id = $1
	`

	apiKey, err := scanAPIKeyRow(r.pool.QueryRow(ctx, query, id))
	if err != nil {
		return nil, err
	}

	return apiKey, nil
}

// ListByUserID retrieves all API keys for a user (paginated)
func (r *APIKeyRepositoryImpl) ListByUserID(ctx context.Context, userID string, limit, offset int) ([]*models.APIKey, error) {
	query := `
		SELECT id, user_id, key_hash, key_prefix, name, scopes, last_used_at, expires_at, revoked_at, created_at, updated_at
		FROM api_keys
		WHERE user_id = $1
		ORDER BY created_at DESC
		LIMIT $2 OFFSET $3
	`

	rows, err := r.pool.Query(ctx, query, userID, limit, offset)
	if err != nil {
		return nil, fmt.Errorf("failed to query api keys: %w", err)
	}

	return scanAPIKeyRows(rows)
}

// CountByUserID returns the count of API keys for a user
func (r *APIKeyRepositoryImpl) CountByUserID(ctx context.Context, userID string) (int, error) {
	query := `SELECT COUNT(*) FROM api_keys WHERE user_id = $1`

	var count int
	err := r.pool.QueryRow(ctx, query, userID).Scan(&count)
	if err != nil {
		return 0, database.MapPostgresError(err)
	}

	return count, nil
}

// UpdateLastUsed updates the last_used_at timestamp for an API key
func (r *APIKeyRepositoryImpl) UpdateLastUsed(ctx context.Context, id string) error {
	query := `UPDATE api_keys SET last_used_at = $1, updated_at = $2 WHERE id = $3`

	_, err := r.pool.Exec(ctx, query, time.Now(), time.Now(), id)
	if err != nil {
		return database.MapPostgresError(err)
	}

	return nil
}

// Revoke soft-deletes an API key by setting revoked_at
func (r *APIKeyRepositoryImpl) Revoke(ctx context.Context, id string) error {
	query := `UPDATE api_keys SET revoked_at = $1, updated_at = $2 WHERE id = $3`

	_, err := r.pool.Exec(ctx, query, time.Now(), time.Now(), id)
	if err != nil {
		return database.MapPostgresError(err)
	}

	return nil
}

// CleanupExpired soft-deletes expired API keys
func (r *APIKeyRepositoryImpl) CleanupExpired(ctx context.Context, beforeTime time.Time) (int64, error) {
	query := `
		UPDATE api_keys
		SET revoked_at = $1, updated_at = $2
		WHERE revoked_at IS NULL AND expires_at IS NOT NULL AND expires_at < $3
	`

	result, err := r.pool.Exec(ctx, query, time.Now(), time.Now(), beforeTime)
	if err != nil {
		return 0, database.MapPostgresError(err)
	}

	return result.RowsAffected(), nil
}
