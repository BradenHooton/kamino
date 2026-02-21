package repositories

import (
	"context"
	"fmt"
	"time"

	"github.com/BradenHooton/kamino/internal/database"
	"github.com/BradenHooton/kamino/internal/models"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

// MFARecoveryRepositoryImpl implements MFARecoveryRepository
type MFARecoveryRepositoryImpl struct {
	pool *pgxpool.Pool
}

// NewMFARecoveryRepository creates a new MFA recovery repository
func NewMFARecoveryRepository(db *database.DB) MFARecoveryRepository {
	return &MFARecoveryRepositoryImpl{pool: db.Pool}
}

// scanMFARecoveryRow scans a recovery request from a database row
func scanMFARecoveryRow(scanner rowScanner) (*models.MFARecoveryRequest, error) {
	req := &models.MFARecoveryRequest{}
	err := scanner.Scan(
		&req.ID,
		&req.UserID,
		&req.InitiatorAdminID,
		&req.ConfirmerAdminID,
		&req.Reason,
		&req.Status,
		&req.CreatedAt,
		&req.ConfirmedAt,
		&req.ExpiresAt,
		&req.ExecutedAt,
	)

	if err != nil {
		return nil, database.MapPostgresError(err)
	}

	return req, nil
}

// Create inserts a new MFA recovery request
func (r *MFARecoveryRepositoryImpl) Create(ctx context.Context, req *models.MFARecoveryRequest) (*models.MFARecoveryRequest, error) {
	query := `
		INSERT INTO mfa_recovery_requests (id, user_id, initiator_admin_id, reason, status, created_at, expires_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
		RETURNING id, user_id, initiator_admin_id, confirmer_admin_id, reason, status, created_at, confirmed_at, expires_at, executed_at
	`

	id := uuid.New()
	now := time.Now()
	expiresAt := now.Add(1 * time.Hour) // Default 1-hour expiry

	newReq, err := scanMFARecoveryRow(r.pool.QueryRow(ctx, query,
		id,
		req.UserID,
		req.InitiatorAdminID,
		req.Reason,
		models.MFARecoveryStatusPending,
		now,
		expiresAt,
	))

	if err != nil {
		return nil, fmt.Errorf("failed to create mfa recovery request: %w", err)
	}

	return newReq, nil
}

// GetByID retrieves a recovery request by ID
func (r *MFARecoveryRepositoryImpl) GetByID(ctx context.Context, id uuid.UUID) (*models.MFARecoveryRequest, error) {
	query := `
		SELECT id, user_id, initiator_admin_id, confirmer_admin_id, reason, status, created_at, confirmed_at, expires_at, executed_at
		FROM mfa_recovery_requests
		WHERE id = $1
	`

	req, err := scanMFARecoveryRow(r.pool.QueryRow(ctx, query, id))
	if err != nil {
		return nil, fmt.Errorf("failed to get mfa recovery request: %w", err)
	}

	return req, nil
}

// GetPendingByUserID checks if there's an existing pending recovery request for a user
func (r *MFARecoveryRepositoryImpl) GetPendingByUserID(ctx context.Context, userID uuid.UUID) (*models.MFARecoveryRequest, error) {
	query := `
		SELECT id, user_id, initiator_admin_id, confirmer_admin_id, reason, status, created_at, confirmed_at, expires_at, executed_at
		FROM mfa_recovery_requests
		WHERE user_id = $1 AND status = 'pending' AND expires_at > CURRENT_TIMESTAMP
		LIMIT 1
	`

	req, err := scanMFARecoveryRow(r.pool.QueryRow(ctx, query, userID))
	if err != nil {
		if err.Error() == "no rows in result set" {
			return nil, nil // No pending request
		}
		return nil, fmt.Errorf("failed to get pending recovery request: %w", err)
	}

	return req, nil
}

// ListPending retrieves all pending recovery requests
func (r *MFARecoveryRepositoryImpl) ListPending(ctx context.Context, limit int, offset int) ([]*models.MFARecoveryRequest, error) {
	query := `
		SELECT id, user_id, initiator_admin_id, confirmer_admin_id, reason, status, created_at, confirmed_at, expires_at, executed_at
		FROM mfa_recovery_requests
		WHERE status = 'pending' AND expires_at > CURRENT_TIMESTAMP
		ORDER BY created_at DESC
		LIMIT $1 OFFSET $2
	`

	rows, err := r.pool.Query(ctx, query, limit, offset)
	if err != nil {
		return nil, fmt.Errorf("failed to list pending recovery requests: %w", err)
	}
	defer rows.Close()

	requests := make([]*models.MFARecoveryRequest, 0)
	for rows.Next() {
		req, err := scanMFARecoveryRow(rows)
		if err != nil {
			return nil, fmt.Errorf("failed to scan recovery request: %w", err)
		}
		requests = append(requests, req)
	}

	if err = rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating recovery requests: %w", err)
	}

	return requests, nil
}

// Confirm marks a recovery request as confirmed by a second admin
func (r *MFARecoveryRepositoryImpl) Confirm(ctx context.Context, id uuid.UUID, confirmerAdminID uuid.UUID) error {
	query := `
		UPDATE mfa_recovery_requests
		SET status = $1, confirmer_admin_id = $2, confirmed_at = CURRENT_TIMESTAMP
		WHERE id = $3 AND status = $4
	`

	result, err := r.pool.Exec(ctx, query,
		models.MFARecoveryStatusConfirmed,
		confirmerAdminID,
		id,
		models.MFARecoveryStatusPending,
	)

	if err != nil {
		return fmt.Errorf("failed to confirm recovery request: %w", err)
	}

	if result.RowsAffected() == 0 {
		return fmt.Errorf("recovery request not found or not in pending status")
	}

	return nil
}

// MarkAsExecuted marks a recovery request as executed
func (r *MFARecoveryRepositoryImpl) MarkAsExecuted(ctx context.Context, id uuid.UUID) error {
	query := `
		UPDATE mfa_recovery_requests
		SET status = $1, executed_at = CURRENT_TIMESTAMP
		WHERE id = $2
	`

	_, err := r.pool.Exec(ctx, query, models.MFARecoveryStatusExecuted, id)
	if err != nil {
		return fmt.Errorf("failed to mark recovery request as executed: %w", err)
	}

	return nil
}

// Cancel marks a recovery request as cancelled
func (r *MFARecoveryRepositoryImpl) Cancel(ctx context.Context, id uuid.UUID) error {
	query := `
		UPDATE mfa_recovery_requests
		SET status = $1
		WHERE id = $2 AND status IN ($3, $4)
	`

	result, err := r.pool.Exec(ctx, query,
		models.MFARecoveryStatusCancelled,
		id,
		models.MFARecoveryStatusPending,
		models.MFARecoveryStatusConfirmed,
	)

	if err != nil {
		return fmt.Errorf("failed to cancel recovery request: %w", err)
	}

	if result.RowsAffected() == 0 {
		return fmt.Errorf("recovery request not found or cannot be cancelled")
	}

	return nil
}

// ExpireOldRequests marks expired requests and returns count
func (r *MFARecoveryRepositoryImpl) ExpireOldRequests(ctx context.Context) (int64, error) {
	query := `
		UPDATE mfa_recovery_requests
		SET status = $1
		WHERE status = $2 AND expires_at <= CURRENT_TIMESTAMP
	`

	result, err := r.pool.Exec(ctx, query,
		models.MFARecoveryStatusExpired,
		models.MFARecoveryStatusPending,
	)

	if err != nil {
		return 0, fmt.Errorf("failed to expire old recovery requests: %w", err)
	}

	return result.RowsAffected(), nil
}
