package services

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/BradenHooton/kamino/internal/auth"
	"github.com/BradenHooton/kamino/internal/models"
	"github.com/BradenHooton/kamino/internal/repositories"
	"github.com/google/uuid"
)

// APIKeyService handles API key business logic
type APIKeyService struct {
	repo         repositories.APIKeyRepository
	keyManager   *auth.APIKeyManager
	auditService *AuditService
	logger       *slog.Logger
}

// NewAPIKeyService creates a new APIKeyService
func NewAPIKeyService(repo repositories.APIKeyRepository, keyManager *auth.APIKeyManager, auditService *AuditService, logger *slog.Logger) *APIKeyService {
	return &APIKeyService{
		repo:         repo,
		keyManager:   keyManager,
		auditService: auditService,
		logger:       logger,
	}
}

// CreateAPIKey generates a new API key for a user
func (s *APIKeyService) CreateAPIKey(ctx context.Context, userID string, name string, scopes []string, expiresAt *time.Time) (*models.GeneratedAPIKey, error) {
	// Validate inputs
	if userID == "" {
		return nil, models.ErrBadRequest
	}
	if name == "" {
		return nil, models.ErrBadRequest
	}
	if err := models.ValidateScopes(scopes); err != nil {
		return nil, err
	}

	// Generate API key (plaintext + hash)
	plainKey, keyHash, err := s.keyManager.GenerateAPIKey()
	if err != nil {
		s.logger.ErrorContext(ctx, "failed to generate api key", slog.Any("error", err))
		return nil, models.ErrInternalServer
	}

	// Get key prefix for display
	keyPrefix, _ := s.keyManager.GetKeyPrefix(plainKey)

	// Create API key model
	now := time.Now()
	apiKey := &models.APIKey{
		ID:        uuid.New().String(),
		UserID:    userID,
		KeyHash:   keyHash,
		KeyPrefix: keyPrefix,
		Name:      name,
		Scopes:    scopes,
		ExpiresAt: expiresAt,
		CreatedAt: now,
		UpdatedAt: now,
	}

	// Store in database
	if err := s.repo.Create(ctx, apiKey); err != nil {
		s.logger.ErrorContext(ctx, "failed to create api key", slog.Any("error", err))
		return nil, models.ErrInternalServer
	}

	// Audit log
	userUUID, _ := uuid.Parse(userID)
	metadata := models.AuditMetadata{
		"key_id":    apiKey.ID,
		"key_prefix": keyPrefix,
		"scopes":    scopes,
		"expires_at": expiresAt,
	}
	_ = s.auditService.LogAPIKeyEvent(ctx, userUUID, models.AuditActionCreate, &apiKey.ID, true, nil, metadata)

	return &models.GeneratedAPIKey{
		PlainKey: plainKey,
		APIKey:   apiKey,
	}, nil
}

// ValidateAPIKey checks if an API key is valid and active
// Returns the API key if valid, nil otherwise
func (s *APIKeyService) ValidateAPIKey(ctx context.Context, plainKey string) (*models.APIKey, error) {
	// Validate format
	keyHash, err := s.keyManager.ValidateAndHashAPIKey(plainKey)
	if err != nil {
		return nil, models.ErrUnauthorized
	}

	// Look up in database
	apiKey, err := s.repo.GetByHash(ctx, keyHash)
	if err != nil {
		if errors.Is(err, models.ErrNotFound) {
			return nil, models.ErrUnauthorized
		}
		// Log database errors but return generic message to prevent enumeration
		s.logger.ErrorContext(ctx, "failed to validate api key", slog.Any("error", err))
		return nil, models.ErrUnauthorized
	}

	// Check if key is active (not revoked, not expired)
	if !apiKey.IsActive() {
		return nil, models.ErrUnauthorized
	}

	// Update last_used_at asynchronously (non-blocking)
	go func() {
		// Create a new context for the goroutine (with timeout to prevent hanging)
		bgCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		if err := s.repo.UpdateLastUsed(bgCtx, apiKey.ID); err != nil {
			s.logger.Warn("failed to update api key last_used_at", slog.String("key_id", apiKey.ID), slog.Any("error", err))
		}
	}()

	return apiKey, nil
}

// ListUserKeys returns all API keys for a user
func (s *APIKeyService) ListUserKeys(ctx context.Context, userID string, limit, offset int) ([]*models.APIKey, error) {
	if userID == "" {
		return nil, models.ErrBadRequest
	}

	// Validate pagination
	if limit <= 0 || limit > 100 {
		limit = 20
	}
	if offset < 0 {
		offset = 0
	}

	apiKeys, err := s.repo.ListByUserID(ctx, userID, limit, offset)
	if err != nil {
		s.logger.ErrorContext(ctx, "failed to list api keys", slog.Any("error", err))
		return nil, models.ErrInternalServer
	}

	// Ensure scopes is never nil (empty array instead)
	for _, key := range apiKeys {
		if key.Scopes == nil {
			key.Scopes = []string{}
		}
	}

	return apiKeys, nil
}

// RevokeAPIKey revokes an API key
func (s *APIKeyService) RevokeAPIKey(ctx context.Context, userID string, keyID string) error {
	if userID == "" || keyID == "" {
		return models.ErrBadRequest
	}

	// Verify key ownership (user can only revoke their own keys)
	apiKey, err := s.repo.GetByID(ctx, keyID)
	if err != nil {
		if errors.Is(err, models.ErrNotFound) {
			return models.ErrNotFound
		}
		s.logger.ErrorContext(ctx, "failed to get api key", slog.Any("error", err))
		return models.ErrInternalServer
	}

	// Check ownership
	if apiKey.UserID != userID {
		return models.ErrForbidden
	}

	// Check if already revoked
	if apiKey.RevokedAt != nil {
		return models.ErrBadRequest // Already revoked
	}

	// Revoke the key
	if err := s.repo.Revoke(ctx, keyID); err != nil {
		s.logger.ErrorContext(ctx, "failed to revoke api key", slog.Any("error", err))
		return models.ErrInternalServer
	}

	// Audit log
	userUUID, _ := uuid.Parse(userID)
	metadata := models.AuditMetadata{
		"key_id":    keyID,
		"key_prefix": apiKey.KeyPrefix,
	}
	_ = s.auditService.LogAPIKeyEvent(ctx, userUUID, "revoke", &keyID, true, nil, metadata)

	return nil
}

// GetAPIKey retrieves a single API key by ID
func (s *APIKeyService) GetAPIKey(ctx context.Context, userID string, keyID string) (*models.APIKey, error) {
	if userID == "" || keyID == "" {
		return nil, models.ErrBadRequest
	}

	apiKey, err := s.repo.GetByID(ctx, keyID)
	if err != nil {
		if errors.Is(err, models.ErrNotFound) {
			return nil, models.ErrNotFound
		}
		s.logger.ErrorContext(ctx, "failed to get api key", slog.Any("error", err))
		return nil, models.ErrInternalServer
	}

	// Check ownership
	if apiKey.UserID != userID {
		return nil, models.ErrForbidden
	}

	return apiKey, nil
}

// CleanupExpiredKeys removes expired API keys
func (s *APIKeyService) CleanupExpiredKeys(ctx context.Context, beforeTime time.Time) (int64, error) {
	rowsAffected, err := s.repo.CleanupExpired(ctx, beforeTime)
	if err != nil {
		s.logger.ErrorContext(ctx, "failed to cleanup expired api keys", slog.Any("error", err))
		return 0, fmt.Errorf("cleanup failed: %w", err)
	}

	if rowsAffected > 0 {
		s.logger.InfoContext(ctx, "cleaned up expired api keys", slog.Int64("rows_affected", rowsAffected))
	}

	return rowsAffected, nil
}
