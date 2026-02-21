package services

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/BradenHooton/kamino/internal/models"
	"github.com/BradenHooton/kamino/internal/repositories"
	"github.com/google/uuid"
)

// MFARecoveryConfig holds MFA recovery configuration
type MFARecoveryConfig struct {
	RequestExpiryHours int
	EmailEnabled       bool
}

// MFARecoveryService handles MFA recovery requests
type MFARecoveryService struct {
	repo         repositories.MFARecoveryRepository
	userRepo     *repositories.UserRepository
	mfaService   *MFAService
	auditService *AuditService
	logger       *slog.Logger
	cfg          MFARecoveryConfig
}

// NewMFARecoveryService creates a new MFA recovery service
func NewMFARecoveryService(
	repo repositories.MFARecoveryRepository,
	userRepo *repositories.UserRepository,
	mfaService *MFAService,
	auditService *AuditService,
	logger *slog.Logger,
	cfg MFARecoveryConfig,
) *MFARecoveryService {
	return &MFARecoveryService{
		repo:         repo,
		userRepo:     userRepo,
		mfaService:   mfaService,
		auditService: auditService,
		logger:       logger,
		cfg:          cfg,
	}
}

// InitiateRecovery starts a new MFA recovery request
func (s *MFARecoveryService) InitiateRecovery(ctx context.Context, initiatorID uuid.UUID, targetUserID uuid.UUID, reason string) (*models.MFARecoveryRequest, error) {
	// Validate initiator is admin
	initiator, err := s.userRepo.GetByID(ctx, initiatorID.String())
	if err != nil {
		s.logger.ErrorContext(ctx, "failed to fetch initiator",
			slog.Any("initiator_id", initiatorID),
			slog.Any("error", err))
		return nil, fmt.Errorf("failed to fetch initiator: %w", err)
	}

	if initiator.Role != "admin" {
		s.logger.WarnContext(ctx, "non-admin attempted to initiate recovery",
			slog.Any("actor_id", initiatorID))
		return nil, fmt.Errorf("only admins can initiate recovery")
	}

	// Verify target user exists and has MFA enabled
	targetUser, err := s.userRepo.GetByID(ctx, targetUserID.String())
	if err != nil {
		s.logger.ErrorContext(ctx, "failed to fetch target user",
			slog.Any("target_user_id", targetUserID),
			slog.Any("error", err))
		return nil, fmt.Errorf("target user not found: %w", err)
	}

	if !targetUser.MFAEnabled {
		return nil, fmt.Errorf("user does not have MFA enabled")
	}

	// Check for existing pending request (prevent duplicates)
	existing, err := s.repo.GetPendingByUserID(ctx, targetUserID)
	if err != nil {
		s.logger.ErrorContext(ctx, "failed to check for pending requests",
			slog.Any("user_id", targetUserID),
			slog.Any("error", err))
		return nil, fmt.Errorf("failed to check for pending requests: %w", err)
	}

	if existing != nil {
		return nil, fmt.Errorf("a recovery request already exists for this user")
	}

	// Create recovery request
	recoveryReq := &models.MFARecoveryRequest{
		UserID:           targetUserID,
		InitiatorAdminID: initiatorID,
		Reason:           reason,
		Status:           models.MFARecoveryStatusPending,
	}

	createdReq, err := s.repo.Create(ctx, recoveryReq)
	if err != nil {
		s.logger.ErrorContext(ctx, "failed to create recovery request",
			slog.Any("user_id", targetUserID),
			slog.Any("error", err))
		return nil, fmt.Errorf("failed to create recovery request: %w", err)
	}

	// Audit log
	requestID := createdReq.ID.String()
	metadata := models.AuditMetadata{
		"user_id":    targetUserID.String(),
		"reason":     reason,
		"request_id": requestID,
	}
	_ = s.auditService.LogUserAction(ctx, initiatorID, targetUserID, "recovery_initiated", "mfa_recovery", &requestID, true, nil, metadata)

	s.logger.InfoContext(ctx, "mfa recovery initiated",
		slog.Any("request_id", createdReq.ID),
		slog.Any("user_id", targetUserID),
		slog.Any("initiator_id", initiatorID))

	return createdReq, nil
}

// ConfirmRecovery confirms a recovery request (second admin approval)
func (s *MFARecoveryService) ConfirmRecovery(ctx context.Context, requestID uuid.UUID, confirmerID uuid.UUID) error {
	// Validate confirmer is admin
	confirmer, err := s.userRepo.GetByID(ctx, confirmerID.String())
	if err != nil {
		return fmt.Errorf("failed to fetch confirmer: %w", err)
	}

	if confirmer.Role != "admin" {
		return fmt.Errorf("only admins can confirm recovery")
	}

	// Fetch recovery request
	req, err := s.repo.GetByID(ctx, requestID)
	if err != nil {
		return fmt.Errorf("failed to fetch recovery request: %w", err)
	}

	// Validate four-eyes principle
	if !req.CanBeConfirmedBy(confirmerID) {
		s.logger.WarnContext(ctx, "invalid recovery confirmation attempt",
			slog.Any("request_id", requestID),
			slog.Any("reason", "confirmer is same as initiator or request not pending"))
		return fmt.Errorf("invalid confirmation: must be different admin or request not pending")
	}

	// Confirm the request
	err = s.repo.Confirm(ctx, requestID, confirmerID)
	if err != nil {
		return fmt.Errorf("failed to confirm recovery request: %w", err)
	}

	// Audit log
	requestIDStr := requestID.String()
	metadata := models.AuditMetadata{
		"request_id":    requestIDStr,
		"confirmed_by":  confirmerID.String(),
	}
	_ = s.auditService.LogUserAction(ctx, confirmerID, req.UserID, "recovery_confirmed", "mfa_recovery", &requestIDStr, true, nil, metadata)

	s.logger.InfoContext(ctx, "mfa recovery confirmed",
		slog.Any("request_id", requestID),
		slog.Any("confirmer_id", confirmerID))

	return nil
}

// ExecuteRecovery executes the recovery (disables MFA)
func (s *MFARecoveryService) ExecuteRecovery(ctx context.Context, requestID uuid.UUID, executorID uuid.UUID) error {
	// Validate executor is admin
	executor, err := s.userRepo.GetByID(ctx, executorID.String())
	if err != nil {
		return fmt.Errorf("failed to fetch executor: %w", err)
	}

	if executor.Role != "admin" {
		return fmt.Errorf("only admins can execute recovery")
	}

	// Fetch recovery request
	req, err := s.repo.GetByID(ctx, requestID)
	if err != nil {
		return fmt.Errorf("failed to fetch recovery request: %w", err)
	}

	// Validate request is confirmed and not expired
	if req.Status != models.MFARecoveryStatusConfirmed {
		return fmt.Errorf("recovery request must be confirmed before execution")
	}

	if req.IsExpired() {
		return fmt.Errorf("recovery request has expired")
	}

	// Disable MFA for the user
	err = s.mfaService.DisableMFA(ctx, req.UserID.String())
	if err != nil {
		s.logger.ErrorContext(ctx, "failed to disable MFA during recovery",
			slog.Any("user_id", req.UserID),
			slog.Any("error", err))
		return fmt.Errorf("failed to disable MFA: %w", err)
	}

	// Mark request as executed
	err = s.repo.MarkAsExecuted(ctx, requestID)
	if err != nil {
		s.logger.ErrorContext(ctx, "failed to mark recovery as executed",
			slog.Any("request_id", requestID),
			slog.Any("error", err))
		return fmt.Errorf("failed to mark recovery as executed: %w", err)
	}

	// Audit log
	requestIDStr := requestID.String()
	metadata := models.AuditMetadata{
		"request_id":    requestIDStr,
		"executed_by":   executorID.String(),
		"mfa_disabled":  true,
	}
	_ = s.auditService.LogUserAction(ctx, executorID, req.UserID, "recovery_executed", "mfa_recovery", &requestIDStr, true, nil, metadata)

	s.logger.InfoContext(ctx, "mfa recovery executed",
		slog.Any("request_id", requestID),
		slog.Any("user_id", req.UserID),
		slog.Any("executor_id", executorID))

	return nil
}

// ListPendingRecoveries lists all pending recovery requests
func (s *MFARecoveryService) ListPendingRecoveries(ctx context.Context, limit int, offset int) ([]*models.MFARecoveryRequest, error) {
	requests, err := s.repo.ListPending(ctx, limit, offset)
	if err != nil {
		return nil, fmt.Errorf("failed to list pending recoveries: %w", err)
	}

	return requests, nil
}

// CancelRecovery cancels a recovery request
func (s *MFARecoveryService) CancelRecovery(ctx context.Context, requestID uuid.UUID, adminID uuid.UUID) error {
	// Validate admin
	admin, err := s.userRepo.GetByID(ctx, adminID.String())
	if err != nil {
		return fmt.Errorf("failed to fetch admin: %w", err)
	}

	if admin.Role != "admin" {
		return fmt.Errorf("only admins can cancel recovery")
	}

	// Fetch recovery request
	req, err := s.repo.GetByID(ctx, requestID)
	if err != nil {
		return fmt.Errorf("failed to fetch recovery request: %w", err)
	}

	// Only initiator or confirmer can cancel
	canCancel := req.InitiatorAdminID == adminID || (req.ConfirmerAdminID != nil && *req.ConfirmerAdminID == adminID)
	if !canCancel {
		s.logger.WarnContext(ctx, "unauthorized recovery cancellation attempt",
			slog.Any("request_id", requestID),
			slog.Any("admin_id", adminID))
		return fmt.Errorf("only initiator or confirmer can cancel")
	}

	// Cancel the request
	err = s.repo.Cancel(ctx, requestID)
	if err != nil {
		return fmt.Errorf("failed to cancel recovery request: %w", err)
	}

	// Audit log
	requestIDStr := requestID.String()
	metadata := models.AuditMetadata{
		"request_id":   requestIDStr,
		"cancelled_by": adminID.String(),
	}
	_ = s.auditService.LogUserAction(ctx, adminID, req.UserID, "recovery_cancelled", "mfa_recovery", &requestIDStr, true, nil, metadata)

	s.logger.InfoContext(ctx, "mfa recovery cancelled",
		slog.Any("request_id", requestID),
		slog.Any("cancelled_by", adminID))

	return nil
}

// CleanupExpiredRequests marks expired requests (called by background cleanup)
func (s *MFARecoveryService) CleanupExpiredRequests(ctx context.Context) (int64, error) {
	count, err := s.repo.ExpireOldRequests(ctx)
	if err != nil {
		s.logger.ErrorContext(ctx, "failed to expire old recovery requests",
			slog.Any("error", err))
		return 0, err
	}

	if count > 0 {
		s.logger.InfoContext(ctx, "expired old mfa recovery requests",
			slog.Int64("count", count))
	}

	return count, nil
}
