package services

import (
	"context"
	"log/slog"
	"time"

	"github.com/BradenHooton/kamino/internal/auth"
	"github.com/BradenHooton/kamino/internal/models"
	"github.com/BradenHooton/kamino/internal/repositories"
	"golang.org/x/crypto/bcrypt"
)

// MFAService handles MFA setup, verification, and management
type MFAService struct {
	deviceRepo  repositories.MFADeviceRepository
	attemptRepo repositories.MFAAttemptRepository
	userRepo    UserRepository
	tm          *auth.TOTPManager
	totpMgr     *auth.TOTPManager
	logger      *slog.Logger
	config      MFAConfig
}

// MFAConfig holds MFA configuration
type MFAConfig struct {
	MaxAttempts     int
	AttemptWindow   time.Duration
	BackupCodeCount int
}

// NewMFAService creates a new MFA service
func NewMFAService(
	deviceRepo repositories.MFADeviceRepository,
	attemptRepo repositories.MFAAttemptRepository,
	userRepo UserRepository,
	totpMgr *auth.TOTPManager,
	logger *slog.Logger,
	config MFAConfig,
) *MFAService {
	return &MFAService{
		deviceRepo:  deviceRepo,
		attemptRepo: attemptRepo,
		userRepo:    userRepo,
		totpMgr:     totpMgr,
		logger:      logger,
		config:      config,
	}
}

// InitiateSetup begins MFA setup and returns QR code and backup codes
func (s *MFAService) InitiateSetup(ctx context.Context, userID, deviceName, email string) (
	*models.MFADevice, []string, string, error,
) {
	// Generate TOTP secret with QR code
	encryptedSecret, nonce, _, qrCode, err := s.totpMgr.GenerateSecretWithQR(deviceName, email)
	if err != nil {
		s.logger.Error("failed to generate TOTP secret", slog.Any("error", err))
		return nil, nil, "", models.ErrInternalServer
	}

	// Generate backup codes
	backupCodes, err := s.totpMgr.GenerateBackupCodes(s.config.BackupCodeCount)
	if err != nil {
		s.logger.Error("failed to generate backup codes", slog.Any("error", err))
		return nil, nil, "", models.ErrInternalServer
	}

	// Create backup code entries with bcrypt hashing
	backupCodeEntries := make([]models.BackupCodeEntry, len(backupCodes))
	for i, code := range backupCodes {
		hash, err := bcrypt.GenerateFromPassword([]byte(code), 14)
		if err != nil {
			s.logger.Error("failed to hash backup code", slog.Any("error", err))
			return nil, nil, "", models.ErrInternalServer
		}
		now := time.Now()
		backupCodeEntries[i] = models.BackupCodeEntry{
			CodeHash:  string(hash),
			UsedAt:    nil,
			CreatedAt: now,
		}
	}

	// Create device in database (not yet verified)
	device := &models.MFADevice{
		UserID:              userID,
		DeviceName:          deviceName,
		TOTPSecretEncrypted: encryptedSecret,
		TOTPSecretNonce:     nonce,
		BackupCodes:         backupCodeEntries,
		CreatedAt:           time.Now(),
		VerifiedAt:          nil,
	}

	if err := s.deviceRepo.Create(ctx, device); err != nil {
		s.logger.Error("failed to create MFA device", slog.Any("error", err))
		return nil, nil, "", models.ErrInternalServer
	}

	s.logger.Info("MFA setup initiated",
		slog.String("user_id", userID),
		slog.String("device_id", device.ID),
		slog.String("device_name", deviceName))

	return device, backupCodes, qrCode, nil
}

// VerifySetup verifies the first TOTP code and enables MFA for the user
func (s *MFAService) VerifySetup(ctx context.Context, userID, deviceID, code string) error {
	// Get the device
	device, err := s.deviceRepo.GetByID(ctx, deviceID)
	if err != nil {
		return models.ErrMFADeviceNotFound
	}

	// Ensure device belongs to the user
	if device.UserID != userID {
		return models.ErrForbidden
	}

	// Device should not be already verified
	if device.IsVerified() {
		return models.ErrConflict
	}

	// Decrypt the secret
	secretBytes, err := s.totpMgr.DecryptSecret(device.TOTPSecretEncrypted, device.TOTPSecretNonce)
	if err != nil {
		s.logger.Error("failed to decrypt TOTP secret", slog.Any("error", err))
		return models.ErrInternalServer
	}

	// Validate the TOTP code
	valid, err := s.totpMgr.ValidateTOTP(secretBytes, code, nil)
	if err != nil {
		s.logger.Error("TOTP validation error", slog.Any("error", err))
		return models.ErrMFAInvalidCode
	}

	if !valid {
		s.logger.Warn("invalid TOTP code during setup", slog.String("user_id", userID))
		return models.ErrMFAInvalidCode
	}

	// Mark device as verified
	if err := s.deviceRepo.MarkAsVerified(ctx, deviceID); err != nil {
		s.logger.Error("failed to mark device as verified", slog.Any("error", err))
		return models.ErrInternalServer
	}

	// Enable MFA for the user
	user, err := s.userRepo.GetByID(ctx, userID)
	if err != nil {
		s.logger.Error("failed to fetch user", slog.Any("error", err))
		return models.ErrInternalServer
	}

	now := time.Now()
	user.MFAEnabled = true
	user.MFAEnrolledAt = &now

	if _, err := s.userRepo.Update(ctx, userID, user); err != nil {
		s.logger.Error("failed to enable MFA for user", slog.Any("error", err))
		return models.ErrInternalServer
	}

	s.logger.Info("MFA setup verified and enabled",
		slog.String("user_id", userID),
		slog.String("device_id", deviceID))

	return nil
}

// VerifyCode validates a TOTP or backup code during login
// Returns: (success, isBackupCode, error)
func (s *MFAService) VerifyCode(ctx context.Context, userID, code, deviceFingerprint, ipAddress string) (bool, error) {
	// Get the primary device
	device, err := s.deviceRepo.GetPrimaryDevice(ctx, userID)
	if err != nil {
		if err == models.ErrNotFound {
			return false, models.ErrMFADeviceNotFound
		}
		s.logger.Error("failed to get primary MFA device", slog.Any("error", err))
		return false, models.ErrInternalServer
	}

	// Check rate limiting
	failedAttempts, err := s.attemptRepo.GetFailedAttemptCount(ctx, userID, time.Now().Add(-s.config.AttemptWindow))
	if err != nil {
		s.logger.Error("failed to check rate limit", slog.Any("error", err))
		return false, models.ErrInternalServer
	}

	if failedAttempts >= s.config.MaxAttempts {
		s.logger.Warn("MFA rate limit exceeded",
			slog.String("user_id", userID),
			slog.Int("attempts", failedAttempts))

		reason := "rate_limited"
		_ = s.recordAttempt(ctx, userID, deviceFingerprint, ipAddress, false, &reason)
		return false, models.ErrMFARateLimited
	}

	// Decrypt the secret
	secretBytes, err := s.totpMgr.DecryptSecret(device.TOTPSecretEncrypted, device.TOTPSecretNonce)
	if err != nil {
		s.logger.Error("failed to decrypt TOTP secret", slog.Any("error", err))
		reason := "internal_error"
		_ = s.recordAttempt(ctx, userID, deviceFingerprint, ipAddress, false, &reason)
		return false, models.ErrInternalServer
	}

	// Try TOTP validation first
	valid, err := s.totpMgr.ValidateTOTP(secretBytes, code, device.LastUsedAt)
	if valid {
		// Update last used time
		if err := s.deviceRepo.UpdateLastUsedAt(ctx, device.ID); err != nil {
			s.logger.Error("failed to update last used at", slog.Any("error", err))
		}
		_ = s.recordAttempt(ctx, userID, deviceFingerprint, ipAddress, true, nil)
		return true, nil
	}

	// Try backup code
	for i, entry := range device.BackupCodes {
		// Skip already used codes
		if entry.UsedAt != nil {
			continue
		}

		// Compare with constant-time comparison
		err := bcrypt.CompareHashAndPassword([]byte(entry.CodeHash), []byte(code))
		if err == nil {
			// Backup code matched! Mark as used
			entry.UsedAt = ptrTime(time.Now())
			device.BackupCodes[i] = entry

			if err := s.deviceRepo.UpdateBackupCodes(ctx, device.ID, device.BackupCodes); err != nil {
				s.logger.Error("failed to update backup codes", slog.Any("error", err))
				reason := "internal_error"
				_ = s.recordAttempt(ctx, userID, deviceFingerprint, ipAddress, false, &reason)
				return false, models.ErrInternalServer
			}

			_ = s.recordAttempt(ctx, userID, deviceFingerprint, ipAddress, true, nil)
			s.logger.Info("backup code used",
				slog.String("user_id", userID),
				slog.Int("code_index", i))
			return true, nil
		}
	}

	// Invalid code
	s.logger.Warn("invalid MFA code",
		slog.String("user_id", userID),
		slog.Int("failed_attempts_now", failedAttempts+1))

	reason := "invalid_code"
	_ = s.recordAttempt(ctx, userID, deviceFingerprint, ipAddress, false, &reason)
	return false, models.ErrMFAInvalidCode
}

// DisableMFA disables MFA for a user after password verification
func (s *MFAService) DisableMFA(ctx context.Context, userID string) error {
	// Delete all MFA devices for the user
	if err := s.deviceRepo.DeleteByUserID(ctx, userID); err != nil {
		s.logger.Error("failed to delete MFA devices", slog.Any("error", err))
		return models.ErrInternalServer
	}

	// Disable MFA flag on user
	user, err := s.userRepo.GetByID(ctx, userID)
	if err != nil {
		s.logger.Error("failed to fetch user", slog.Any("error", err))
		return models.ErrInternalServer
	}

	user.MFAEnabled = false
	user.MFAEnrolledAt = nil

	if _, err := s.userRepo.Update(ctx, userID, user); err != nil {
		s.logger.Error("failed to disable MFA for user", slog.Any("error", err))
		return models.ErrInternalServer
	}

	s.logger.Info("MFA disabled", slog.String("user_id", userID))
	return nil
}

// GetStatus returns MFA status and devices for a user
func (s *MFAService) GetStatus(ctx context.Context, userID string) (*models.MFAStatus, error) {
	user, err := s.userRepo.GetByID(ctx, userID)
	if err != nil {
		return nil, models.ErrNotFound
	}

	devices, err := s.deviceRepo.GetByUserID(ctx, userID)
	if err != nil {
		s.logger.Error("failed to get MFA devices", slog.Any("error", err))
		return nil, models.ErrInternalServer
	}

	status := &models.MFAStatus{
		MFAEnabled: user.MFAEnabled,
		Devices:    devices,
		EnrolledAt: user.MFAEnrolledAt,
	}

	return status, nil
}

// recordAttempt records an MFA verification attempt
func (s *MFAService) recordAttempt(ctx context.Context, userID, deviceFingerprint, ipAddress string, success bool, failureReason *string) error {
	attempt := &models.MFAVerificationAttempt{
		UserID:           userID,
		DeviceFingerprint: deviceFingerprint,
		IPAddress:        ipAddress,
		Success:          success,
		FailureReason:    failureReason,
	}

	if err := s.attemptRepo.RecordAttempt(ctx, attempt); err != nil {
		s.logger.Error("failed to record MFA attempt", slog.Any("error", err))
		return err
	}

	return nil
}

// Helper function to create a pointer to time.Time
func ptrTime(t time.Time) *time.Time {
	return &t
}
