package repositories

import (
	"context"
	"fmt"
	"time"

	"github.com/BradenHooton/kamino/internal/models"
	"github.com/jackc/pgx/v5/pgxpool"
)

// MFAAttemptRepository defines MFA verification attempt persistence operations
type MFAAttemptRepository interface {
	RecordAttempt(ctx context.Context, attempt *models.MFAVerificationAttempt) error
	GetFailedAttemptCount(ctx context.Context, userID string, since time.Time) (int, error)
	GetFailedAttemptsForDevice(ctx context.Context, deviceFingerprint string, since time.Time) (int, error)
	GetFailedAttemptsForIP(ctx context.Context, ipAddress string, since time.Time) (int, error)
	DeleteExpiredAttempts(ctx context.Context, threshold time.Time) error
}

// mfaAttemptRepoImpl implements MFAAttemptRepository
type mfaAttemptRepoImpl struct {
	db *pgxpool.Pool
}

// NewMFAAttemptRepository creates a new MFA attempt repository
func NewMFAAttemptRepository(db *pgxpool.Pool) MFAAttemptRepository {
	return &mfaAttemptRepoImpl{db: db}
}

// RecordAttempt records a verification attempt
func (r *mfaAttemptRepoImpl) RecordAttempt(ctx context.Context, attempt *models.MFAVerificationAttempt) error {
	query := `
		INSERT INTO mfa_verification_attempts
			(user_id, device_fingerprint, ip_address, success, failure_reason, attempted_at)
		VALUES ($1, $2, $3, $4, $5, NOW())
		RETURNING id, attempted_at
	`

	err := r.db.QueryRow(ctx, query,
		attempt.UserID,
		attempt.DeviceFingerprint,
		attempt.IPAddress,
		attempt.Success,
		attempt.FailureReason,
	).Scan(&attempt.ID, &attempt.AttemptedAt)

	if err != nil {
		return fmt.Errorf("failed to record MFA attempt: %w", err)
	}

	return nil
}

// GetFailedAttemptCount retrieves the count of failed attempts for a user in the last N minutes
func (r *mfaAttemptRepoImpl) GetFailedAttemptCount(ctx context.Context, userID string, since time.Time) (int, error) {
	query := `
		SELECT COUNT(*)
		FROM mfa_verification_attempts
		WHERE user_id = $1 AND success = false AND attempted_at >= $2
	`

	var count int
	err := r.db.QueryRow(ctx, query, userID, since).Scan(&count)
	if err != nil {
		return 0, fmt.Errorf("failed to get failed attempt count: %w", err)
	}

	return count, nil
}

// GetFailedAttemptsForDevice retrieves failed attempts for a device fingerprint
func (r *mfaAttemptRepoImpl) GetFailedAttemptsForDevice(ctx context.Context, deviceFingerprint string, since time.Time) (int, error) {
	query := `
		SELECT COUNT(*)
		FROM mfa_verification_attempts
		WHERE device_fingerprint = $1 AND success = false AND attempted_at >= $2
	`

	var count int
	err := r.db.QueryRow(ctx, query, deviceFingerprint, since).Scan(&count)
	if err != nil {
		return 0, fmt.Errorf("failed to get device failed attempt count: %w", err)
	}

	return count, nil
}

// GetFailedAttemptsForIP retrieves failed attempts for an IP address
func (r *mfaAttemptRepoImpl) GetFailedAttemptsForIP(ctx context.Context, ipAddress string, since time.Time) (int, error) {
	query := `
		SELECT COUNT(*)
		FROM mfa_verification_attempts
		WHERE ip_address = $1::inet AND success = false AND attempted_at >= $2
	`

	var count int
	err := r.db.QueryRow(ctx, query, ipAddress, since).Scan(&count)
	if err != nil {
		return 0, fmt.Errorf("failed to get IP failed attempt count: %w", err)
	}

	return count, nil
}

// DeleteExpiredAttempts deletes attempts older than the threshold
func (r *mfaAttemptRepoImpl) DeleteExpiredAttempts(ctx context.Context, threshold time.Time) error {
	query := `DELETE FROM mfa_verification_attempts WHERE attempted_at < $1`

	_, err := r.db.Exec(ctx, query, threshold)
	if err != nil {
		return fmt.Errorf("failed to delete expired MFA attempts: %w", err)
	}

	return nil
}
