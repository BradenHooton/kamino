package background

import (
	"context"
	"log/slog"
	"time"

	"github.com/BradenHooton/kamino/internal/repositories"
)

// CleanupManager periodically removes expired revoked tokens from the database
type CleanupManager struct {
	revokeRepo *repositories.TokenRevocationRepository
	logger     *slog.Logger
	interval   time.Duration
	stopCh     chan struct{}
}

// NewCleanupManager creates a new cleanup manager
func NewCleanupManager(
	revokeRepo *repositories.TokenRevocationRepository,
	logger *slog.Logger,
	interval time.Duration,
) *CleanupManager {
	return &CleanupManager{
		revokeRepo: revokeRepo,
		logger:     logger,
		interval:   interval,
		stopCh:     make(chan struct{}),
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

// runCleanup removes expired tokens from the database
func (cm *CleanupManager) runCleanup(ctx context.Context) {
	cm.logger.Info("starting expired token cleanup")

	cleanupCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	rowsDeleted, err := cm.revokeRepo.CleanupExpiredTokens(cleanupCtx)
	if err != nil {
		cm.logger.Error("failed to cleanup expired tokens", slog.Any("error", err))
		return
	}

	if rowsDeleted > 0 {
		cm.logger.Info("expired token cleanup completed", slog.Int64("rows_deleted", rowsDeleted))
	}
}

// Stop signals the cleanup manager to stop
func (cm *CleanupManager) Stop() {
	close(cm.stopCh)
}
