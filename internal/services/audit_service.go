package services

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"log/slog"
	"time"

	"github.com/BradenHooton/kamino/internal/config"
	"github.com/BradenHooton/kamino/internal/models"
	"github.com/BradenHooton/kamino/internal/repositories"
	"github.com/google/uuid"
)

// AuditService handles audit logging with dual-write pattern (slog + database)
type AuditService struct {
	repo   *repositories.AuditLogRepository
	logger *slog.Logger
	cfg    *config.AuditConfig
}

// NewAuditService creates a new AuditService
func NewAuditService(repo *repositories.AuditLogRepository, logger *slog.Logger, cfg *config.AuditConfig) *AuditService {
	return &AuditService{
		repo:   repo,
		logger: logger,
		cfg:    cfg,
	}
}

// LogAuthEvent logs authentication-related events (login, logout, register)
func (s *AuditService) LogAuthEvent(ctx context.Context, eventType string, actorID *uuid.UUID, action string, success bool, failureReason *string, ipAddress, userAgent *string, metadata models.AuditMetadata) error {
	log := &models.AuditLog{
		EventType:     eventType,
		ActorID:       actorID,
		Action:        action,
		Success:       success,
		FailureReason: failureReason,
		IPAddress:     ipAddress,
		UserAgent:     userAgent,
		Metadata:      metadata,
	}

	// Dual-write: immediate slog output
	if success {
		s.logger.InfoContext(ctx, "audit event",
			slog.String("event_type", eventType),
			slog.Any("actor_id", actorID),
			slog.String("action", action),
			slog.Any("metadata", metadata),
		)
	} else {
		s.logger.WarnContext(ctx, "audit event failed",
			slog.String("event_type", eventType),
			slog.Any("actor_id", actorID),
			slog.String("action", action),
			slog.String("failure_reason", *failureReason),
			slog.Any("metadata", metadata),
		)
	}

	// Persist to database (non-blocking)
	_, err := s.repo.Create(ctx, log)
	if err != nil {
		s.logger.ErrorContext(ctx, "failed to persist audit log",
			slog.String("event_type", eventType),
			slog.Any("error", err),
		)
		// Non-critical: don't fail the authentication if audit logging fails
		return nil
	}

	return nil
}

// LogUserAction logs user-related actions (role changes, permissions, deletions)
func (s *AuditService) LogUserAction(ctx context.Context, actorID, targetID uuid.UUID, action string, resourceType string, resourceID *string, success bool, failureReason *string, metadata models.AuditMetadata) error {
	log := &models.AuditLog{
		EventType:     "user_action",
		ActorID:       &actorID,
		TargetID:      &targetID,
		ResourceType:  &resourceType,
		ResourceID:    resourceID,
		Action:        action,
		Success:       success,
		FailureReason: failureReason,
		Metadata:      metadata,
	}

	// Dual-write: immediate slog output
	if success {
		s.logger.InfoContext(ctx, "user action",
			slog.Any("actor_id", actorID),
			slog.Any("target_id", targetID),
			slog.String("action", action),
			slog.String("resource_type", resourceType),
			slog.Any("metadata", metadata),
		)
	} else {
		s.logger.WarnContext(ctx, "user action failed",
			slog.Any("actor_id", actorID),
			slog.Any("target_id", targetID),
			slog.String("action", action),
			slog.String("resource_type", resourceType),
			slog.String("failure_reason", *failureReason),
			slog.Any("metadata", metadata),
		)
	}

	// Persist to database
	_, err := s.repo.Create(ctx, log)
	if err != nil {
		s.logger.ErrorContext(ctx, "failed to persist audit log",
			slog.String("action", action),
			slog.Any("error", err),
		)
		return nil
	}

	return nil
}

// LogMFAEvent logs MFA-related events
func (s *AuditService) LogMFAEvent(ctx context.Context, actorID uuid.UUID, action string, success bool, failureReason *string, metadata models.AuditMetadata) error {
	log := &models.AuditLog{
		EventType:     models.AuditEventTypeMFASetup,
		ActorID:       &actorID,
		Action:        action,
		Success:       success,
		FailureReason: failureReason,
		Metadata:      metadata,
	}

	if action == "disable" {
		log.EventType = models.AuditEventTypeMFADisable
	}

	// Dual-write: immediate slog output
	if success {
		s.logger.InfoContext(ctx, "mfa event",
			slog.Any("actor_id", actorID),
			slog.String("action", action),
		)
	} else {
		s.logger.WarnContext(ctx, "mfa event failed",
			slog.Any("actor_id", actorID),
			slog.String("action", action),
			slog.String("failure_reason", *failureReason),
		)
	}

	// Persist to database
	_, err := s.repo.Create(ctx, log)
	if err != nil {
		s.logger.ErrorContext(ctx, "failed to persist audit log",
			slog.String("action", action),
			slog.Any("error", err),
		)
		return nil
	}

	return nil
}

// LogAPIKeyEvent logs API key operations
func (s *AuditService) LogAPIKeyEvent(ctx context.Context, actorID uuid.UUID, action string, keyID *string, success bool, failureReason *string, metadata models.AuditMetadata) error {
	resourceType := models.AuditResourceTypeAPIKey
	log := &models.AuditLog{
		EventType:     models.AuditEventTypeAPIKeyOp,
		ActorID:       &actorID,
		ResourceType:  &resourceType,
		ResourceID:    keyID,
		Action:        action,
		Success:       success,
		FailureReason: failureReason,
		Metadata:      metadata,
	}

	// Dual-write: immediate slog output
	if success {
		s.logger.InfoContext(ctx, "api key operation",
			slog.Any("actor_id", actorID),
			slog.String("action", action),
		)
	} else {
		s.logger.WarnContext(ctx, "api key operation failed",
			slog.Any("actor_id", actorID),
			slog.String("action", action),
			slog.String("failure_reason", *failureReason),
		)
	}

	// Persist to database
	_, err := s.repo.Create(ctx, log)
	if err != nil {
		s.logger.ErrorContext(ctx, "failed to persist audit log",
			slog.String("action", action),
			slog.Any("error", err),
		)
		return nil
	}

	return nil
}

// GetUserAuditTrail retrieves audit trail for a specific user
func (s *AuditService) GetUserAuditTrail(ctx context.Context, userID uuid.UUID, limit int, offset int) ([]*models.AuditLog, error) {
	if limit <= 0 || limit > 100 {
		limit = 50
	}
	if offset < 0 {
		offset = 0
	}

	logs, err := s.repo.GetByUserID(ctx, userID, limit, offset)
	if err != nil {
		return nil, fmt.Errorf("failed to get user audit trail: %w", err)
	}

	return logs, nil
}

// GetCountForUser returns the count of audit logs for a user
func (s *AuditService) GetCountForUser(ctx context.Context, userID uuid.UUID) (int64, error) {
	count, err := s.repo.CountByUserID(ctx, userID)
	if err != nil {
		return 0, fmt.Errorf("failed to count audit logs: %w", err)
	}
	return count, nil
}

// LogStatusChange logs a user status-change event (suspended, activated, locked) with a
// specific event type so dashboard queries can filter by event_type column.
func (s *AuditService) LogStatusChange(ctx context.Context, eventType string, actorID, targetID uuid.UUID, reason string, metadata models.AuditMetadata) error {
	resourceType := models.AuditResourceTypeUser
	targetIDStr := targetID.String()
	if metadata == nil {
		metadata = make(models.AuditMetadata)
	}
	metadata["reason"] = reason

	log := &models.AuditLog{
		EventType:    eventType,
		ActorID:      &actorID,
		TargetID:     &targetID,
		ResourceType: &resourceType,
		ResourceID:   &targetIDStr,
		Action:       models.AuditActionUpdate,
		Success:      true,
		Metadata:     metadata,
	}

	s.logger.InfoContext(ctx, "user status change",
		slog.String("event_type", eventType),
		slog.Any("actor_id", actorID),
		slog.Any("target_id", targetID),
		slog.String("reason", reason),
	)

	if _, err := s.repo.Create(ctx, log); err != nil {
		s.logger.ErrorContext(ctx, "failed to persist status change audit log",
			slog.String("event_type", eventType),
			slog.Any("error", err),
		)
		// Non-critical: don't fail the operation if audit logging fails
	}
	return nil
}

// cryptoRandFloat64 returns a secure random float between 0.0 and 1.0
// Uses crypto/rand for security-sensitive sampling decisions
func cryptoRandFloat64() (float64, error) {
	randomBytes := make([]byte, 8)
	_, err := rand.Read(randomBytes)
	if err != nil {
		return 0, err
	}

	// Convert bytes to uint64 and normalize to 0.0-1.0
	randomValue := binary.BigEndian.Uint64(randomBytes)
	return float64(randomValue) / float64(^uint64(0)), nil
}

// LogAPIKeyUsage logs API key usage asynchronously (fire-and-forget pattern)
// Captures endpoint access, HTTP method, scopes, and response status codes
// Non-blocking: errors are logged but don't fail the request
// Respects config flags: LogAPIKeyUsage (enable/disable) and APIKeyUsageSampling (0.0-1.0)
func (s *AuditService) LogAPIKeyUsage(
	ctx context.Context,
	actorID string, // User ID
	keyID string,
	keyPrefix string,
	endpoint string,
	method string,
	requiredScopes []string,
	statusCode int,
	ipAddress *string,
	userAgent *string,
) {
	// Check if API key usage logging is enabled via config
	if !s.cfg.LogAPIKeyUsage {
		return
	}

	// Check sampling rate (0.0-1.0, where 1.0 = log all)
	if s.cfg.APIKeyUsageSampling < 1.0 {
		randomVal, err := cryptoRandFloat64()
		if err != nil || randomVal > s.cfg.APIKeyUsageSampling {
			return // Skip logging based on sampling rate
		}
	}

	// Fire-and-forget: spawn goroutine with independent timeout
	go func() {
		// Create timeout context: 5 seconds max for audit logging
		auditCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		// Parse actorID string to UUID
		actorUUID, err := uuid.Parse(actorID)
		if err != nil {
			s.logger.ErrorContext(auditCtx, "invalid actor id in api key usage log",
				slog.String("actor_id", actorID),
				slog.Any("error", err),
			)
			return
		}

		resourceType := models.AuditResourceTypeAPIKey
		log := &models.AuditLog{
			EventType:    models.AuditEventTypeAPIKeyUsage,
			ActorID:      &actorUUID,
			ResourceType: &resourceType,
			ResourceID:   &keyID,
			Action:       method,
			Success:      statusCode >= 200 && statusCode < 400,
			IPAddress:    ipAddress,
			UserAgent:    userAgent,
			Metadata: models.NewAPIKeyUsageMetadata(
				endpoint,
				method,
				requiredScopes,
				statusCode,
				keyPrefix,
				ipAddress,
				userAgent,
			),
		}

		// Immediate slog output for real-time visibility
		s.logger.InfoContext(auditCtx, "api key usage",
			slog.String("key_prefix", keyPrefix),
			slog.String("actor_id", actorID),
			slog.String("endpoint", endpoint),
			slog.String("method", method),
			slog.Int("status_code", statusCode),
		)

		// Persist to database
		if _, err := s.repo.Create(auditCtx, log); err != nil {
			s.logger.ErrorContext(auditCtx, "failed to persist api key usage audit log",
				slog.String("key_prefix", keyPrefix),
				slog.Any("error", err),
			)
		}
	}()
}
