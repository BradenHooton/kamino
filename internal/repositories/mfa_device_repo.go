package repositories

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/BradenHooton/kamino/internal/models"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

// MFADeviceRepository defines MFA device persistence operations
type MFADeviceRepository interface {
	Create(ctx context.Context, device *models.MFADevice) error
	GetByID(ctx context.Context, deviceID string) (*models.MFADevice, error)
	GetByUserID(ctx context.Context, userID string) ([]models.MFADevice, error)
	GetVerifiedByUserID(ctx context.Context, userID string) ([]models.MFADevice, error)
	GetPrimaryDevice(ctx context.Context, userID string) (*models.MFADevice, error)
	MarkAsVerified(ctx context.Context, deviceID string) error
	UpdateLastUsedAt(ctx context.Context, deviceID string) error
	UpdateBackupCodes(ctx context.Context, deviceID string, codes []models.BackupCodeEntry) error
	Delete(ctx context.Context, deviceID string) error
	DeleteByUserID(ctx context.Context, userID string) error
}

// mfaDeviceRepoImpl implements MFADeviceRepository
type mfaDeviceRepoImpl struct {
	db *pgxpool.Pool
}

// NewMFADeviceRepository creates a new MFA device repository
func NewMFADeviceRepository(db *pgxpool.Pool) MFADeviceRepository {
	return &mfaDeviceRepoImpl{db: db}
}

// Create inserts a new MFA device
func (r *mfaDeviceRepoImpl) Create(ctx context.Context, device *models.MFADevice) error {
	backupCodesJSON, err := json.Marshal(device.BackupCodes)
	if err != nil {
		return fmt.Errorf("failed to marshal backup codes: %w", err)
	}

	query := `
		INSERT INTO mfa_devices
			(user_id, device_name, totp_secret_encrypted, totp_secret_nonce, backup_codes)
		VALUES ($1, $2, $3, $4, $5)
		RETURNING id, created_at
	`

	err = r.db.QueryRow(ctx, query,
		device.UserID,
		device.DeviceName,
		device.TOTPSecretEncrypted,
		device.TOTPSecretNonce,
		backupCodesJSON,
	).Scan(&device.ID, &device.CreatedAt)

	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) {
			switch pgErr.Code {
			case "23503": // Foreign key violation
				return models.ErrNotFound
			}
		}
		return fmt.Errorf("failed to create MFA device: %w", err)
	}

	return nil
}

// GetByID retrieves an MFA device by ID
func (r *mfaDeviceRepoImpl) GetByID(ctx context.Context, deviceID string) (*models.MFADevice, error) {
	device := &models.MFADevice{}
	var backupCodesJSON []byte

	query := `
		SELECT id, user_id, device_name, totp_secret_encrypted, totp_secret_nonce,
		       backup_codes, last_used_at, created_at, verified_at
		FROM mfa_devices
		WHERE id = $1
	`

	err := r.db.QueryRow(ctx, query, deviceID).Scan(
		&device.ID,
		&device.UserID,
		&device.DeviceName,
		&device.TOTPSecretEncrypted,
		&device.TOTPSecretNonce,
		&backupCodesJSON,
		&device.LastUsedAt,
		&device.CreatedAt,
		&device.VerifiedAt,
	)

	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, models.ErrNotFound
		}
		return nil, fmt.Errorf("failed to get MFA device: %w", err)
	}

	if err := json.Unmarshal(backupCodesJSON, &device.BackupCodes); err != nil {
		return nil, fmt.Errorf("failed to unmarshal backup codes: %w", err)
	}

	return device, nil
}

// GetByUserID retrieves all MFA devices for a user
func (r *mfaDeviceRepoImpl) GetByUserID(ctx context.Context, userID string) ([]models.MFADevice, error) {
	query := `
		SELECT id, user_id, device_name, totp_secret_encrypted, totp_secret_nonce,
		       backup_codes, last_used_at, created_at, verified_at
		FROM mfa_devices
		WHERE user_id = $1
		ORDER BY created_at DESC
	`

	rows, err := r.db.Query(ctx, query, userID)
	if err != nil {
		return nil, fmt.Errorf("failed to query MFA devices: %w", err)
	}
	defer rows.Close()

	var devices []models.MFADevice
	for rows.Next() {
		device := models.MFADevice{}
		var backupCodesJSON []byte

		if err := rows.Scan(
			&device.ID,
			&device.UserID,
			&device.DeviceName,
			&device.TOTPSecretEncrypted,
			&device.TOTPSecretNonce,
			&backupCodesJSON,
			&device.LastUsedAt,
			&device.CreatedAt,
			&device.VerifiedAt,
		); err != nil {
			return nil, fmt.Errorf("failed to scan MFA device: %w", err)
		}

		if err := json.Unmarshal(backupCodesJSON, &device.BackupCodes); err != nil {
			return nil, fmt.Errorf("failed to unmarshal backup codes: %w", err)
		}

		devices = append(devices, device)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating MFA devices: %w", err)
	}

	return devices, nil
}

// GetVerifiedByUserID retrieves only verified MFA devices for a user
func (r *mfaDeviceRepoImpl) GetVerifiedByUserID(ctx context.Context, userID string) ([]models.MFADevice, error) {
	query := `
		SELECT id, user_id, device_name, totp_secret_encrypted, totp_secret_nonce,
		       backup_codes, last_used_at, created_at, verified_at
		FROM mfa_devices
		WHERE user_id = $1 AND verified_at IS NOT NULL
		ORDER BY created_at DESC
	`

	rows, err := r.db.Query(ctx, query, userID)
	if err != nil {
		return nil, fmt.Errorf("failed to query verified MFA devices: %w", err)
	}
	defer rows.Close()

	var devices []models.MFADevice
	for rows.Next() {
		device := models.MFADevice{}
		var backupCodesJSON []byte

		if err := rows.Scan(
			&device.ID,
			&device.UserID,
			&device.DeviceName,
			&device.TOTPSecretEncrypted,
			&device.TOTPSecretNonce,
			&backupCodesJSON,
			&device.LastUsedAt,
			&device.CreatedAt,
			&device.VerifiedAt,
		); err != nil {
			return nil, fmt.Errorf("failed to scan MFA device: %w", err)
		}

		if err := json.Unmarshal(backupCodesJSON, &device.BackupCodes); err != nil {
			return nil, fmt.Errorf("failed to unmarshal backup codes: %w", err)
		}

		devices = append(devices, device)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating verified MFA devices: %w", err)
	}

	return devices, nil
}

// GetPrimaryDevice retrieves the oldest verified device (primary)
func (r *mfaDeviceRepoImpl) GetPrimaryDevice(ctx context.Context, userID string) (*models.MFADevice, error) {
	device := &models.MFADevice{}
	var backupCodesJSON []byte

	query := `
		SELECT id, user_id, device_name, totp_secret_encrypted, totp_secret_nonce,
		       backup_codes, last_used_at, created_at, verified_at
		FROM mfa_devices
		WHERE user_id = $1 AND verified_at IS NOT NULL
		ORDER BY verified_at ASC
		LIMIT 1
	`

	err := r.db.QueryRow(ctx, query, userID).Scan(
		&device.ID,
		&device.UserID,
		&device.DeviceName,
		&device.TOTPSecretEncrypted,
		&device.TOTPSecretNonce,
		&backupCodesJSON,
		&device.LastUsedAt,
		&device.CreatedAt,
		&device.VerifiedAt,
	)

	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, models.ErrNotFound
		}
		return nil, fmt.Errorf("failed to get primary MFA device: %w", err)
	}

	if err := json.Unmarshal(backupCodesJSON, &device.BackupCodes); err != nil {
		return nil, fmt.Errorf("failed to unmarshal backup codes: %w", err)
	}

	return device, nil
}

// MarkAsVerified marks a device as verified
func (r *mfaDeviceRepoImpl) MarkAsVerified(ctx context.Context, deviceID string) error {
	query := `
		UPDATE mfa_devices
		SET verified_at = NOW()
		WHERE id = $1
		RETURNING verified_at
	`

	var verifiedAt time.Time
	err := r.db.QueryRow(ctx, query, deviceID).Scan(&verifiedAt)

	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return models.ErrNotFound
		}
		return fmt.Errorf("failed to mark device as verified: %w", err)
	}

	return nil
}

// UpdateLastUsedAt updates the last_used_at timestamp
func (r *mfaDeviceRepoImpl) UpdateLastUsedAt(ctx context.Context, deviceID string) error {
	query := `
		UPDATE mfa_devices
		SET last_used_at = NOW()
		WHERE id = $1
	`

	commandTag, err := r.db.Exec(ctx, query, deviceID)
	if err != nil {
		return fmt.Errorf("failed to update last_used_at: %w", err)
	}

	if commandTag.RowsAffected() == 0 {
		return models.ErrNotFound
	}

	return nil
}

// UpdateBackupCodes updates the backup codes for a device
func (r *mfaDeviceRepoImpl) UpdateBackupCodes(ctx context.Context, deviceID string, codes []models.BackupCodeEntry) error {
	backupCodesJSON, err := json.Marshal(codes)
	if err != nil {
		return fmt.Errorf("failed to marshal backup codes: %w", err)
	}

	query := `
		UPDATE mfa_devices
		SET backup_codes = $1
		WHERE id = $2
	`

	commandTag, err := r.db.Exec(ctx, query, backupCodesJSON, deviceID)
	if err != nil {
		return fmt.Errorf("failed to update backup codes: %w", err)
	}

	if commandTag.RowsAffected() == 0 {
		return models.ErrNotFound
	}

	return nil
}

// Delete removes an MFA device
func (r *mfaDeviceRepoImpl) Delete(ctx context.Context, deviceID string) error {
	query := `DELETE FROM mfa_devices WHERE id = $1`

	commandTag, err := r.db.Exec(ctx, query, deviceID)
	if err != nil {
		return fmt.Errorf("failed to delete MFA device: %w", err)
	}

	if commandTag.RowsAffected() == 0 {
		return models.ErrNotFound
	}

	return nil
}

// DeleteByUserID removes all MFA devices for a user
func (r *mfaDeviceRepoImpl) DeleteByUserID(ctx context.Context, userID string) error {
	query := `DELETE FROM mfa_devices WHERE user_id = $1`

	_, err := r.db.Exec(ctx, query, userID)
	if err != nil {
		return fmt.Errorf("failed to delete user's MFA devices: %w", err)
	}

	return nil
}
