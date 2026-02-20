package services

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/BradenHooton/kamino/internal/models"
	"github.com/BradenHooton/kamino/internal/repositories"
	"github.com/google/uuid"
)

// AuditService handles audit logging with dual-write pattern (slog + database)
type AuditService struct {
	repo   repositories.AuditLogRepository
	logger *slog.Logger
}

// NewAuditService creates a new AuditService
func NewAuditService(repo repositories.AuditLogRepository, logger *slog.Logger) *AuditService {
	return &AuditService{
		repo:   repo,
		logger: logger,
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
