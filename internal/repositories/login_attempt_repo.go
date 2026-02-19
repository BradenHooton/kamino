package repositories

import (
	"context"
	"time"

	"github.com/BradenHooton/kamino/internal/database"
	"github.com/BradenHooton/kamino/internal/models"
	"github.com/jackc/pgx/v5"
)

// LoginAttemptRepository handles database operations for login attempts
type LoginAttemptRepository struct {
	db *database.DB
}

// NewLoginAttemptRepository creates a new LoginAttemptRepository
func NewLoginAttemptRepository(db *database.DB) *LoginAttemptRepository {
	return &LoginAttemptRepository{db: db}
}

// RecordAttempt records a login attempt in the database
func (r *LoginAttemptRepository) RecordAttempt(ctx context.Context, attempt *models.LoginAttempt) error {
	query := `
		INSERT INTO login_attempts (email, ip_address, user_agent, success, failure_reason, device_fingerprint, expires_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
	`

	_, err := r.db.Pool.Exec(ctx, query,
		attempt.Email,
		attempt.IPAddress,
		attempt.UserAgent,
		attempt.Success,
		attempt.FailureReason,
		attempt.DeviceFingerprint,
		attempt.ExpiresAt,
	)

	return err
}

// GetFailedAttemptCount returns the number of failed attempts for an email within a time window
func (r *LoginAttemptRepository) GetFailedAttemptCount(ctx context.Context, email string, since time.Time) (int, error) {
	query := `
		SELECT COUNT(*) FROM login_attempts
		WHERE email = $1 AND success = false AND attempt_time >= $2
	`

	var count int
	err := r.db.Pool.QueryRow(ctx, query, email, since).Scan(&count)
	return count, err
}

// GetRecentFailureTime returns the timestamp of the most recent failed attempt for an email
func (r *LoginAttemptRepository) GetRecentFailureTime(ctx context.Context, email string, since time.Time) (*time.Time, error) {
	query := `
		SELECT attempt_time FROM login_attempts
		WHERE email = $1 AND success = false AND attempt_time >= $2
		ORDER BY attempt_time DESC
		LIMIT 1
	`

	var failureTime time.Time
	err := r.db.Pool.QueryRow(ctx, query, email, since).Scan(&failureTime)
	if err == pgx.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	return &failureTime, nil
}

// GetLastSuccessTime returns the timestamp of the most recent successful login for an email
func (r *LoginAttemptRepository) GetLastSuccessTime(ctx context.Context, email string) (*time.Time, error) {
	query := `
		SELECT attempt_time FROM login_attempts
		WHERE email = $1 AND success = true
		ORDER BY attempt_time DESC
		LIMIT 1
	`

	var successTime time.Time
	err := r.db.Pool.QueryRow(ctx, query, email).Scan(&successTime)
	if err == pgx.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	return &successTime, nil
}

// GetFailedAttemptCountByIP returns the number of failed attempts from an IP within a time window
func (r *LoginAttemptRepository) GetFailedAttemptCountByIP(ctx context.Context, ipAddress string, since time.Time) (int, error) {
	query := `
		SELECT COUNT(*) FROM login_attempts
		WHERE ip_address = $1 AND success = false AND attempt_time >= $2
	`

	var count int
	err := r.db.Pool.QueryRow(ctx, query, ipAddress, since).Scan(&count)
	return count, err
}

// GetFailedAttemptCountByDevice returns the number of failed attempts from a device within a time window
func (r *LoginAttemptRepository) GetFailedAttemptCountByDevice(ctx context.Context, fingerprint string, since time.Time) (int, error) {
	query := `
		SELECT COUNT(*) FROM login_attempts
		WHERE device_fingerprint = $1 AND success = false AND attempt_time >= $2
	`

	var count int
	err := r.db.Pool.QueryRow(ctx, query, fingerprint, since).Scan(&count)
	return count, err
}

// DeleteExpiredAttempts removes login attempts older than the expiration time
func (r *LoginAttemptRepository) DeleteExpiredAttempts(ctx context.Context) error {
	query := `DELETE FROM login_attempts WHERE expires_at <= CURRENT_TIMESTAMP`
	_, err := r.db.Pool.Exec(ctx, query)
	return err
}
