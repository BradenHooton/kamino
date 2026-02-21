package repositories

import (
	"context"

	"github.com/BradenHooton/kamino/internal/models"
	"github.com/google/uuid"
)

// MFARecoveryRepository defines methods for MFA recovery request persistence
type MFARecoveryRepository interface {
	// Create inserts a new MFA recovery request
	Create(ctx context.Context, req *models.MFARecoveryRequest) (*models.MFARecoveryRequest, error)

	// GetByID retrieves a recovery request by ID
	GetByID(ctx context.Context, id uuid.UUID) (*models.MFARecoveryRequest, error)

	// GetPendingByUserID checks if there's an existing pending recovery request for a user
	GetPendingByUserID(ctx context.Context, userID uuid.UUID) (*models.MFARecoveryRequest, error)

	// ListPending retrieves all pending recovery requests (for admin dashboard)
	ListPending(ctx context.Context, limit int, offset int) ([]*models.MFARecoveryRequest, error)

	// Confirm marks a recovery request as confirmed by a second admin
	Confirm(ctx context.Context, id uuid.UUID, confirmerAdminID uuid.UUID) error

	// MarkAsExecuted marks a recovery request as executed
	MarkAsExecuted(ctx context.Context, id uuid.UUID) error

	// Cancel marks a recovery request as cancelled
	Cancel(ctx context.Context, id uuid.UUID) error

	// ExpireOldRequests marks expired requests and returns count
	ExpireOldRequests(ctx context.Context) (int64, error)
}
