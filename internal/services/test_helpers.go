package services

import (
	"context"
	"fmt"
	"time"

	"github.com/BradenHooton/kamino/internal/models"
	"github.com/golang-jwt/jwt/v5"
)

// MockUserRepository implements UserRepository for testing
type MockUserRepository struct {
	GetByIDFunc   func(ctx context.Context, id string) (*models.User, error)
	ListFunc      func(ctx context.Context, limit, offset int) ([]*models.User, error)
	CreateFunc    func(ctx context.Context, user *models.User) (*models.User, error)
	UpdateFunc    func(ctx context.Context, id string, user *models.User) (*models.User, error)
	DeleteFunc    func(ctx context.Context, id string) error
	GetByEmailFunc func(ctx context.Context, email string) (*models.User, error)
}

func (m *MockUserRepository) GetByID(ctx context.Context, id string) (*models.User, error) {
	if m.GetByIDFunc != nil {
		return m.GetByIDFunc(ctx, id)
	}
	return nil, models.ErrNotFound
}

func (m *MockUserRepository) List(ctx context.Context, limit, offset int) ([]*models.User, error) {
	if m.ListFunc != nil {
		return m.ListFunc(ctx, limit, offset)
	}
	return []*models.User{}, nil
}

func (m *MockUserRepository) Create(ctx context.Context, user *models.User) (*models.User, error) {
	if m.CreateFunc != nil {
		return m.CreateFunc(ctx, user)
	}
	return nil, models.ErrInternalServer
}

func (m *MockUserRepository) Update(ctx context.Context, id string, user *models.User) (*models.User, error) {
	if m.UpdateFunc != nil {
		return m.UpdateFunc(ctx, id, user)
	}
	return nil, models.ErrInternalServer
}

func (m *MockUserRepository) Delete(ctx context.Context, id string) error {
	if m.DeleteFunc != nil {
		return m.DeleteFunc(ctx, id)
	}
	return nil
}

func (m *MockUserRepository) GetByEmail(ctx context.Context, email string) (*models.User, error) {
	if m.GetByEmailFunc != nil {
		return m.GetByEmailFunc(ctx, email)
	}
	return nil, models.ErrNotFound
}

// MockTokenRevocationRepository implements TokenRevocationRepository for testing
type MockTokenRevocationRepository struct {
	RevokeTokenFunc       func(ctx context.Context, jti, userID, tokenType string, expiresAt time.Time, reason string) error
	RevokeAllUserTokensFunc func(ctx context.Context, userID, reason string) error
	IsTokenRevokedFunc    func(ctx context.Context, jti string) (bool, error)
}

func (m *MockTokenRevocationRepository) RevokeToken(ctx context.Context, jti, userID, tokenType string, expiresAt time.Time, reason string) error {
	if m.RevokeTokenFunc != nil {
		return m.RevokeTokenFunc(ctx, jti, userID, tokenType, expiresAt, reason)
	}
	return nil
}

func (m *MockTokenRevocationRepository) RevokeAllUserTokens(ctx context.Context, userID, reason string) error {
	if m.RevokeAllUserTokensFunc != nil {
		return m.RevokeAllUserTokensFunc(ctx, userID, reason)
	}
	return nil
}

func (m *MockTokenRevocationRepository) IsTokenRevoked(ctx context.Context, jti string) (bool, error) {
	if m.IsTokenRevokedFunc != nil {
		return m.IsTokenRevokedFunc(ctx, jti)
	}
	return false, nil
}

// MockEmailVerificationRepository implements EmailVerificationRepository for testing
type MockEmailVerificationRepository struct {
	CreateFunc            func(ctx context.Context, userID, tokenHash, email string, expiresAt time.Time) (*models.EmailVerificationToken, error)
	GetByTokenHashFunc    func(ctx context.Context, tokenHash string) (*models.EmailVerificationToken, error)
	MarkAsUsedFunc        func(ctx context.Context, id string) error
	DeleteByUserIDFunc    func(ctx context.Context, userID string) error
	CleanupExpiredFunc    func(ctx context.Context) (int64, error)
	GetPendingByEmailFunc func(ctx context.Context, email string) (*models.EmailVerificationToken, error)
}

func (m *MockEmailVerificationRepository) Create(ctx context.Context, userID, tokenHash, email string, expiresAt time.Time) (*models.EmailVerificationToken, error) {
	if m.CreateFunc != nil {
		return m.CreateFunc(ctx, userID, tokenHash, email, expiresAt)
	}
	return &models.EmailVerificationToken{ID: "token_123", UserID: userID, Email: email, ExpiresAt: expiresAt}, nil
}

func (m *MockEmailVerificationRepository) GetByTokenHash(ctx context.Context, tokenHash string) (*models.EmailVerificationToken, error) {
	if m.GetByTokenHashFunc != nil {
		return m.GetByTokenHashFunc(ctx, tokenHash)
	}
	return nil, models.ErrNotFound
}

func (m *MockEmailVerificationRepository) MarkAsUsed(ctx context.Context, id string) error {
	if m.MarkAsUsedFunc != nil {
		return m.MarkAsUsedFunc(ctx, id)
	}
	return nil
}

func (m *MockEmailVerificationRepository) DeleteByUserID(ctx context.Context, userID string) error {
	if m.DeleteByUserIDFunc != nil {
		return m.DeleteByUserIDFunc(ctx, userID)
	}
	return nil
}

func (m *MockEmailVerificationRepository) CleanupExpired(ctx context.Context) (int64, error) {
	if m.CleanupExpiredFunc != nil {
		return m.CleanupExpiredFunc(ctx)
	}
	return 0, nil
}

func (m *MockEmailVerificationRepository) GetPendingByEmail(ctx context.Context, email string) (*models.EmailVerificationToken, error) {
	if m.GetPendingByEmailFunc != nil {
		return m.GetPendingByEmailFunc(ctx, email)
	}
	return nil, models.ErrNotFound
}

// MockEmailService implements EmailService for testing
type MockEmailService struct {
	SendVerificationEmailFunc func(ctx context.Context, email, token string, expiresAt time.Time) error
}

func (m *MockEmailService) SendVerificationEmail(ctx context.Context, email, token string, expiresAt time.Time) error {
	if m.SendVerificationEmailFunc != nil {
		return m.SendVerificationEmailFunc(ctx, email, token, expiresAt)
	}
	return nil
}

// TestUserBuilder helps construct test users
func NewTestUser(id, email, name string) *models.User {
	now := time.Now()
	return &models.User{
		ID:            id,
		Email:         email,
		Name:          name,
		EmailVerified: true,
		Status:        "active",
		Role:          "user",
		CreatedAt:     now,
		UpdatedAt:     now,
	}
}

// TestUserWithPassword creates a user with hashed password
func NewTestUserWithPassword(id, email, name, passwordHash string) *models.User {
	user := NewTestUser(id, email, name)
	user.PasswordHash = passwordHash
	return user
}

// TestUserUnverified creates a user with unverified email
func NewTestUserUnverified(id, email, name string) *models.User {
	user := NewTestUser(id, email, name)
	user.EmailVerified = false
	return user
}

// TestUserWithStatus creates a user with specified status
func NewTestUserWithStatus(id, email, name, status string) *models.User {
	user := NewTestUser(id, email, name)
	user.Status = status
	return user
}

// TestUserLocked creates a locked user
func NewTestUserLocked(id, email, name string) *models.User {
	user := NewTestUser(id, email, name)
	lockedUntil := time.Now().Add(30 * time.Minute)
	user.LockedUntil = &lockedUntil
	return user
}

// TestEmailVerificationToken creates a test token
func NewTestEmailVerificationToken(id, userID, email string, expiresAt time.Time) *models.EmailVerificationToken {
	return &models.EmailVerificationToken{
		ID:        id,
		UserID:    userID,
		Email:     email,
		ExpiresAt: expiresAt,
		CreatedAt: time.Now(),
		UsedAt:    nil,
	}
}

// TestEmailVerificationTokenExpired creates an expired token
func NewTestEmailVerificationTokenExpired(id, userID, email string) *models.EmailVerificationToken {
	token := NewTestEmailVerificationToken(id, userID, email, time.Now().Add(-1*time.Hour))
	return token
}

// TestEmailVerificationTokenUsed creates a used token
func NewTestEmailVerificationTokenUsed(id, userID, email string) *models.EmailVerificationToken {
	now := time.Now()
	token := NewTestEmailVerificationToken(id, userID, email, now.Add(24*time.Hour))
	token.UsedAt = &now
	return token
}

// FailingRateLimitService is used for testing auth service
type MockRateLimitService struct {
	CheckRateLimitFunc    func(ctx context.Context, email, ipAddress, userAgent string) (bool, *time.Duration, error)
	RecordLoginAttemptFunc func(ctx context.Context, email, ipAddress, userAgent string, success bool, failureReason *string) error
}

func (m *MockRateLimitService) CheckRateLimit(ctx context.Context, email, ipAddress, userAgent string) (bool, *time.Duration, error) {
	if m.CheckRateLimitFunc != nil {
		return m.CheckRateLimitFunc(ctx, email, ipAddress, userAgent)
	}
	return true, nil, nil
}

func (m *MockRateLimitService) RecordLoginAttempt(ctx context.Context, email, ipAddress, userAgent string, success bool, failureReason *string) error {
	if m.RecordLoginAttemptFunc != nil {
		return m.RecordLoginAttemptFunc(ctx, email, ipAddress, userAgent, success, failureReason)
	}
	return nil
}

// MockTokenManager is a minimal mock for TokenManager
type MockTokenManager struct {
	GenerateAccessTokenFunc  func(userID, email string) (string, error)
	GenerateRefreshTokenFunc func(userID, email string) (string, error)
	GenerateMFATokenFunc     func(userID, email string) (string, error)
	ValidateTokenFunc        func(tokenString string) (*models.TokenClaims, error)
}

func (m *MockTokenManager) GenerateAccessToken(userID, email string) (string, error) {
	if m.GenerateAccessTokenFunc != nil {
		return m.GenerateAccessTokenFunc(userID, email)
	}
	return "access_token_" + userID, nil
}

func (m *MockTokenManager) GenerateRefreshToken(userID, email string) (string, error) {
	if m.GenerateRefreshTokenFunc != nil {
		return m.GenerateRefreshTokenFunc(userID, email)
	}
	return "refresh_token_" + userID, nil
}

func (m *MockTokenManager) GenerateMFAToken(userID, email string) (string, error) {
	if m.GenerateMFATokenFunc != nil {
		return m.GenerateMFATokenFunc(userID, email)
	}
	return "mfa_token_" + userID, nil
}

func (m *MockTokenManager) ValidateToken(tokenString string) (*models.TokenClaims, error) {
	if m.ValidateTokenFunc != nil {
		return m.ValidateTokenFunc(tokenString)
	}
	now := time.Now()
	expiresAt := now.Add(15 * time.Minute)
	return &models.TokenClaims{
		Type:   "access",
		UserID: "user123",
		Email:  "user@example.com",
		RegisteredClaims: jwt.RegisteredClaims{
			ID:        "jti_123",
			ExpiresAt: jwt.NewNumericDate(expiresAt),
			IssuedAt:  jwt.NewNumericDate(now),
		},
	}, nil
}

// Helper to create valid token claims
func NewTokenClaims(userID, email, tokenType string) *models.TokenClaims {
	now := time.Now()
	expiresAt := now.Add(15 * time.Minute)
	return &models.TokenClaims{
		Type:   tokenType,
		UserID: userID,
		Email:  email,
		RegisteredClaims: jwt.RegisteredClaims{
			ID:        fmt.Sprintf("jti_%s_%d", userID, now.Unix()),
			ExpiresAt: jwt.NewNumericDate(expiresAt),
			IssuedAt:  jwt.NewNumericDate(now),
		},
	}
}

// Helper to create expired token claims
func NewTokenClaimsExpired(userID, email, tokenType string) *models.TokenClaims {
	now := time.Now()
	expiresAt := now.Add(-1 * time.Minute)
	return &models.TokenClaims{
		Type:   tokenType,
		UserID: userID,
		Email:  email,
		RegisteredClaims: jwt.RegisteredClaims{
			ID:        fmt.Sprintf("jti_%s_%d", userID, now.Unix()),
			ExpiresAt: jwt.NewNumericDate(expiresAt),
			IssuedAt:  jwt.NewNumericDate(now),
		},
	}
}

// ============================================================================
// MFA Test Mocks and Builders
// ============================================================================

// MockMFADeviceRepository implements MFADeviceRepository for testing
type MockMFADeviceRepository struct {
	CreateFunc                func(ctx context.Context, device *models.MFADevice) error
	GetByIDFunc               func(ctx context.Context, deviceID string) (*models.MFADevice, error)
	GetByUserIDFunc           func(ctx context.Context, userID string) ([]models.MFADevice, error)
	GetVerifiedByUserIDFunc   func(ctx context.Context, userID string) ([]models.MFADevice, error)
	GetPrimaryDeviceFunc      func(ctx context.Context, userID string) (*models.MFADevice, error)
	MarkAsVerifiedFunc        func(ctx context.Context, deviceID string) error
	UpdateLastUsedAtFunc      func(ctx context.Context, deviceID string) error
	UpdateBackupCodesFunc     func(ctx context.Context, deviceID string, codes []models.BackupCodeEntry) error
	DeleteFunc                func(ctx context.Context, deviceID string) error
	DeleteByUserIDFunc        func(ctx context.Context, userID string) error
}

func (m *MockMFADeviceRepository) Create(ctx context.Context, device *models.MFADevice) error {
	if m.CreateFunc != nil {
		return m.CreateFunc(ctx, device)
	}
	// Auto-generate ID for testing
	device.ID = "device_" + device.UserID + "_test"
	return nil
}

func (m *MockMFADeviceRepository) GetByID(ctx context.Context, deviceID string) (*models.MFADevice, error) {
	if m.GetByIDFunc != nil {
		return m.GetByIDFunc(ctx, deviceID)
	}
	return nil, models.ErrMFADeviceNotFound
}

func (m *MockMFADeviceRepository) GetByUserID(ctx context.Context, userID string) ([]models.MFADevice, error) {
	if m.GetByUserIDFunc != nil {
		return m.GetByUserIDFunc(ctx, userID)
	}
	return []models.MFADevice{}, nil
}

func (m *MockMFADeviceRepository) GetVerifiedByUserID(ctx context.Context, userID string) ([]models.MFADevice, error) {
	if m.GetVerifiedByUserIDFunc != nil {
		return m.GetVerifiedByUserIDFunc(ctx, userID)
	}
	return []models.MFADevice{}, nil
}

func (m *MockMFADeviceRepository) GetPrimaryDevice(ctx context.Context, userID string) (*models.MFADevice, error) {
	if m.GetPrimaryDeviceFunc != nil {
		return m.GetPrimaryDeviceFunc(ctx, userID)
	}
	return nil, models.ErrMFADeviceNotFound
}

func (m *MockMFADeviceRepository) MarkAsVerified(ctx context.Context, deviceID string) error {
	if m.MarkAsVerifiedFunc != nil {
		return m.MarkAsVerifiedFunc(ctx, deviceID)
	}
	return nil
}

func (m *MockMFADeviceRepository) UpdateLastUsedAt(ctx context.Context, deviceID string) error {
	if m.UpdateLastUsedAtFunc != nil {
		return m.UpdateLastUsedAtFunc(ctx, deviceID)
	}
	return nil
}

func (m *MockMFADeviceRepository) UpdateBackupCodes(ctx context.Context, deviceID string, codes []models.BackupCodeEntry) error {
	if m.UpdateBackupCodesFunc != nil {
		return m.UpdateBackupCodesFunc(ctx, deviceID, codes)
	}
	return nil
}

func (m *MockMFADeviceRepository) Delete(ctx context.Context, deviceID string) error {
	if m.DeleteFunc != nil {
		return m.DeleteFunc(ctx, deviceID)
	}
	return nil
}

func (m *MockMFADeviceRepository) DeleteByUserID(ctx context.Context, userID string) error {
	if m.DeleteByUserIDFunc != nil {
		return m.DeleteByUserIDFunc(ctx, userID)
	}
	return nil
}

// MockMFAAttemptRepository implements MFAAttemptRepository for testing
type MockMFAAttemptRepository struct {
	RecordAttemptFunc              func(ctx context.Context, attempt *models.MFAVerificationAttempt) error
	GetFailedAttemptCountFunc      func(ctx context.Context, userID string, since time.Time) (int, error)
	GetFailedAttemptsForDeviceFunc func(ctx context.Context, deviceFingerprint string, since time.Time) (int, error)
	GetFailedAttemptsForIPFunc     func(ctx context.Context, ipAddress string, since time.Time) (int, error)
	DeleteExpiredAttemptsFunc      func(ctx context.Context, threshold time.Time) error
}

func (m *MockMFAAttemptRepository) RecordAttempt(ctx context.Context, attempt *models.MFAVerificationAttempt) error {
	if m.RecordAttemptFunc != nil {
		return m.RecordAttemptFunc(ctx, attempt)
	}
	return nil
}

func (m *MockMFAAttemptRepository) GetFailedAttemptCount(ctx context.Context, userID string, since time.Time) (int, error) {
	if m.GetFailedAttemptCountFunc != nil {
		return m.GetFailedAttemptCountFunc(ctx, userID, since)
	}
	return 0, nil
}

func (m *MockMFAAttemptRepository) GetFailedAttemptsForDevice(ctx context.Context, deviceFingerprint string, since time.Time) (int, error) {
	if m.GetFailedAttemptsForDeviceFunc != nil {
		return m.GetFailedAttemptsForDeviceFunc(ctx, deviceFingerprint, since)
	}
	return 0, nil
}

func (m *MockMFAAttemptRepository) GetFailedAttemptsForIP(ctx context.Context, ipAddress string, since time.Time) (int, error) {
	if m.GetFailedAttemptsForIPFunc != nil {
		return m.GetFailedAttemptsForIPFunc(ctx, ipAddress, since)
	}
	return 0, nil
}

func (m *MockMFAAttemptRepository) DeleteExpiredAttempts(ctx context.Context, threshold time.Time) error {
	if m.DeleteExpiredAttemptsFunc != nil {
		return m.DeleteExpiredAttemptsFunc(ctx, threshold)
	}
	return nil
}

// ============================================================================
// MFA Test Data Builders
// ============================================================================

// NewTestMFADevice creates a verified MFA device with backup codes
func NewTestMFADevice(id, userID, deviceName string, encrypted, nonce []byte, backupCodes []string) *models.MFADevice {
	now := time.Now()
	backupCodeEntries := make([]models.BackupCodeEntry, len(backupCodes))
	for i, code := range backupCodes {
		// In real tests, these would be bcrypt hashes; here we use the code for simplicity
		backupCodeEntries[i] = models.BackupCodeEntry{
			CodeHash:  code, // In tests, this will be replaced with actual hashes
			UsedAt:    nil,
			CreatedAt: now,
		}
	}

	return &models.MFADevice{
		ID:                     id,
		UserID:                 userID,
		DeviceName:             deviceName,
		TOTPSecretEncrypted:    encrypted,
		TOTPSecretNonce:        nonce,
		BackupCodes:            backupCodeEntries,
		LastUsedAt:             nil,
		CreatedAt:              now,
		VerifiedAt:             &now, // Verified by default
	}
}

// NewTestMFADeviceUnverified creates an unverified MFA device (VerifiedAt is nil)
func NewTestMFADeviceUnverified(id, userID, deviceName string, encrypted, nonce []byte, backupCodes []string) *models.MFADevice {
	device := NewTestMFADevice(id, userID, deviceName, encrypted, nonce, backupCodes)
	device.VerifiedAt = nil
	return device
}

// NewTestBackupCodes creates backup code entries with specified count
// Uses placeholder hashes (in real tests, these would be bcrypt hashes)
func NewTestBackupCodes(count int, used []bool) []models.BackupCodeEntry {
	entries := make([]models.BackupCodeEntry, count)
	now := time.Now()
	for i := 0; i < count; i++ {
		entry := models.BackupCodeEntry{
			CodeHash:  fmt.Sprintf("hash_%d", i),
			CreatedAt: now,
			UsedAt:    nil,
		}
		if i < len(used) && used[i] {
			usedTime := now.Add(-1 * time.Hour)
			entry.UsedAt = &usedTime
		}
		entries[i] = entry
	}
	return entries
}

// NewTestBackupCodeUsed creates a single used backup code entry
func NewTestBackupCodeUsed(codeHash string) models.BackupCodeEntry {
	now := time.Now()
	usedTime := now.Add(-1 * time.Hour)
	return models.BackupCodeEntry{
		CodeHash:  codeHash,
		CreatedAt: now,
		UsedAt:    &usedTime,
	}
}

// NewTestUserWithMFAEnabled creates a user with MFA enabled
func NewTestUserWithMFAEnabled(id, email, name string) *models.User {
	user := NewTestUser(id, email, name)
	now := time.Now()
	user.MFAEnabled = true
	user.MFAEnrolledAt = &now
	return user
}

// NewTestMFAAttempt creates an MFA verification attempt
func NewTestMFAAttempt(userID, deviceFingerprint, ipAddress string, success bool) *models.MFAVerificationAttempt {
	attempt := &models.MFAVerificationAttempt{
		ID:                fmt.Sprintf("attempt_%s_%d", userID, time.Now().Unix()),
		UserID:            userID,
		DeviceFingerprint: deviceFingerprint,
		IPAddress:         ipAddress,
		Success:           success,
		AttemptedAt:       time.Now(),
	}
	if !success {
		reason := "invalid_code"
		attempt.FailureReason = &reason
	}
	return attempt
}

// ============================================================================
// AuthService Test Mocks
// ============================================================================

// MockTimingDelay implements auth.TimingDelay interface for testing
type MockTimingDelay struct {
	WaitFromFunc func(startTime time.Time, succeeded bool)
}

func (m *MockTimingDelay) WaitFrom(startTime time.Time, succeeded bool) {
	if m.WaitFromFunc != nil {
		m.WaitFromFunc(startTime, succeeded)
	}
}

// MockEmailVerificationService implements EmailVerificationService interface for testing
type MockEmailVerificationService struct {
	SendVerificationEmailFunc func(ctx context.Context, userID, email string) error
	VerifyEmailFunc           func(ctx context.Context, userID, tokenString string) error
	GetStatusFunc             func(ctx context.Context, userID string) (bool, error)
	ResendVerificationEmailFunc func(ctx context.Context, userID, email string) error
}

func (m *MockEmailVerificationService) SendVerificationEmail(ctx context.Context, userID, email string) error {
	if m.SendVerificationEmailFunc != nil {
		return m.SendVerificationEmailFunc(ctx, userID, email)
	}
	return nil
}

func (m *MockEmailVerificationService) VerifyEmail(ctx context.Context, userID, tokenString string) error {
	if m.VerifyEmailFunc != nil {
		return m.VerifyEmailFunc(ctx, userID, tokenString)
	}
	return nil
}

func (m *MockEmailVerificationService) GetStatus(ctx context.Context, userID string) (bool, error) {
	if m.GetStatusFunc != nil {
		return m.GetStatusFunc(ctx, userID)
	}
	return true, nil
}

func (m *MockEmailVerificationService) ResendVerificationEmail(ctx context.Context, userID, email string) error {
	if m.ResendVerificationEmailFunc != nil {
		return m.ResendVerificationEmailFunc(ctx, userID, email)
	}
	return nil
}

// MockAuditLogger is a no-op audit logger for testing
type MockAuditLogger struct {
}

func (m *MockAuditLogger) LogAccountAction(ctx context.Context, userID, action string, details map[string]interface{}, ipAddress string) {
	// No-op for testing
}

func (m *MockAuditLogger) LogAuthenticationAttempt(ctx context.Context, email string, success bool, ipAddress string) {
	// No-op for testing
}

// MockAuditLogRepository implements AuditLogRepository for testing
type MockAuditLogRepository struct {
	CreateFunc              func(ctx context.Context, log *models.AuditLog) (*models.AuditLog, error)
	GetByUserIDFunc         func(ctx context.Context, userID string, limit int, offset int) ([]*models.AuditLog, error)
	GetByActorIDFunc        func(ctx context.Context, actorID string, limit int, offset int) ([]*models.AuditLog, error)
	GetByEventTypeFunc      func(ctx context.Context, eventType string, limit int, offset int) ([]*models.AuditLog, error)
	GetFailedAttemptsFunc   func(ctx context.Context, email string, since time.Time) (int, error)
	CleanupFunc             func(ctx context.Context, olderThanDays int) (int64, error)
	CountByUserIDFunc       func(ctx context.Context, userID string) (int64, error)
	GetByAPIKeyIDFunc       func(ctx context.Context, keyID string, limit int, offset int) ([]*models.AuditLog, error)
	CountByAPIKeyIDFunc     func(ctx context.Context, keyID string) (int64, error)
	CreatedLogs             []*models.AuditLog
}

func (m *MockAuditLogRepository) Create(ctx context.Context, log *models.AuditLog) (*models.AuditLog, error) {
	if m.CreateFunc != nil {
		return m.CreateFunc(ctx, log)
	}
	m.CreatedLogs = append(m.CreatedLogs, log)
	return log, nil
}

func (m *MockAuditLogRepository) GetByUserID(ctx context.Context, userID string, limit int, offset int) ([]*models.AuditLog, error) {
	if m.GetByUserIDFunc != nil {
		return m.GetByUserIDFunc(ctx, userID, limit, offset)
	}
	return []*models.AuditLog{}, nil
}

func (m *MockAuditLogRepository) GetByActorID(ctx context.Context, actorID string, limit int, offset int) ([]*models.AuditLog, error) {
	if m.GetByActorIDFunc != nil {
		return m.GetByActorIDFunc(ctx, actorID, limit, offset)
	}
	return []*models.AuditLog{}, nil
}

func (m *MockAuditLogRepository) GetByEventType(ctx context.Context, eventType string, limit int, offset int) ([]*models.AuditLog, error) {
	if m.GetByEventTypeFunc != nil {
		return m.GetByEventTypeFunc(ctx, eventType, limit, offset)
	}
	return []*models.AuditLog{}, nil
}

func (m *MockAuditLogRepository) GetFailedAttempts(ctx context.Context, email string, since time.Time) (int, error) {
	if m.GetFailedAttemptsFunc != nil {
		return m.GetFailedAttemptsFunc(ctx, email, since)
	}
	return 0, nil
}

func (m *MockAuditLogRepository) Cleanup(ctx context.Context, olderThanDays int) (int64, error) {
	if m.CleanupFunc != nil {
		return m.CleanupFunc(ctx, olderThanDays)
	}
	return 0, nil
}

func (m *MockAuditLogRepository) CountByUserID(ctx context.Context, userID string) (int64, error) {
	if m.CountByUserIDFunc != nil {
		return m.CountByUserIDFunc(ctx, userID)
	}
	return 0, nil
}

func (m *MockAuditLogRepository) GetByAPIKeyID(ctx context.Context, keyID string, limit int, offset int) ([]*models.AuditLog, error) {
	if m.GetByAPIKeyIDFunc != nil {
		return m.GetByAPIKeyIDFunc(ctx, keyID, limit, offset)
	}
	return []*models.AuditLog{}, nil
}

func (m *MockAuditLogRepository) CountByAPIKeyID(ctx context.Context, keyID string) (int64, error) {
	if m.CountByAPIKeyIDFunc != nil {
		return m.CountByAPIKeyIDFunc(ctx, keyID)
	}
	return 0, nil
}
