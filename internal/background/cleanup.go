package background

import (
	"context"
	"log/slog"
	"time"

	"github.com/BradenHooton/kamino/internal/repositories"
)

// CleanupManager periodically removes expired revoked tokens, login attempts, and email verification tokens from the database
type CleanupManager struct {
	revokeRepo               *repositories.TokenRevocationRepository
	loginAttemptRepo         *repositories.LoginAttemptRepository
	emailVerificationRepo    *repositories.EmailVerificationRepository
	logger                   *slog.Logger
	interval                 time.Duration
	stopCh                   chan struct{}
}

// NewCleanupManager creates a new cleanup manager
func NewCleanupManager(
	revokeRepo *repositories.TokenRevocationRepository,
	loginAttemptRepo *repositories.LoginAttemptRepository,
	emailVerificationRepo *repositories.EmailVerificationRepository,
	logger *slog.Logger,
	interval time.Duration,
) *CleanupManager {
	return &CleanupManager{
		revokeRepo:            revokeRepo,
		loginAttemptRepo:      loginAttemptRepo,
		emailVerificationRepo: emailVerificationRepo,
		logger:                logger,
		interval:              interval,
		stopCh:                make(chan struct{}),
	}
}

// Start begins the periodic cleanup task
func (cm *CleanupManager) Start(ctx context.Context) {
	ticker := time.NewTicker(cm.interval)
	defer ticker.Stop()

	// Run immediately on startup
	cm.runCleanup(ctx)

	for {
		select {
		case <-ticker.C:
			cm.runCleanup(ctx)
		case <-cm.stopCh:
			cm.logger.Info("cleanup manager stopped")
			return
		case <-ctx.Done():
			cm.logger.Info("cleanup manager context cancelled")
			return
		}
	}
}

// runCleanup removes expired tokens and login attempts from the database
func (cm *CleanupManager) runCleanup(ctx context.Context) {
	cm.logger.Info("starting cleanup of expired records")

	cleanupCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	// Cleanup expired revoked tokens
	rowsDeleted, err := cm.revokeRepo.CleanupExpiredTokens(cleanupCtx)
	if err != nil {
		cm.logger.Error("failed to cleanup expired tokens", slog.Any("error", err))
	} else if rowsDeleted > 0 {
		cm.logger.Info("expired token cleanup completed", slog.Int64("rows_deleted", rowsDeleted))
	}

	// Cleanup expired login attempts
	err = cm.loginAttemptRepo.DeleteExpiredAttempts(cleanupCtx)
	if err != nil {
		cm.logger.Error("failed to cleanup expired login attempts", slog.Any("error", err))
	} else {
		cm.logger.Info("expired login attempt cleanup completed")
	}

	// Cleanup expired email verification tokens (30+ days old)
	if cm.emailVerificationRepo != nil {
		rowsDeleted, err := cm.emailVerificationRepo.CleanupExpired(cleanupCtx)
		if err != nil {
			cm.logger.Error("failed to cleanup expired email verification tokens", slog.Any("error", err))
		} else if rowsDeleted > 0 {
			cm.logger.Info("email verification token cleanup completed", slog.Int64("rows_deleted", rowsDeleted))
		}
	}
}

// Stop signals the cleanup manager to stop
func (cm *CleanupManager) Stop() {
	close(cm.stopCh)
}
