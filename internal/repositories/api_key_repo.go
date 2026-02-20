package repositories

import (
	"context"
	"time"

	"github.com/BradenHooton/kamino/internal/models"
)

// APIKeyRepository defines the interface for API key data access operations
type APIKeyRepository interface {
	// Create stores a new API key in the database
	Create(ctx context.Context, apiKey *models.APIKey) error

	// GetByHash retrieves an API key by its hash (active only)
	GetByHash(ctx context.Context, keyHash string) (*models.APIKey, error)

	// GetByID retrieves an API key by its ID
	GetByID(ctx context.Context, id string) (*models.APIKey, error)

	// ListByUserID retrieves all API keys for a user (active and revoked)
	ListByUserID(ctx context.Context, userID string, limit, offset int) ([]*models.APIKey, error)

	// CountByUserID returns the count of API keys for a user
	CountByUserID(ctx context.Context, userID string) (int, error)

	// UpdateLastUsed updates the last_used_at timestamp (non-blocking operation)
	UpdateLastUsed(ctx context.Context, id string) error

	// Revoke soft-deletes an API key by setting revoked_at timestamp
	Revoke(ctx context.Context, id string) error

	// CleanupExpired soft-deletes API keys that are expired or revoked (for background cleanup)
	// Returns the count of affected rows
	CleanupExpired(ctx context.Context, beforeTime time.Time) (int64, error)
}
