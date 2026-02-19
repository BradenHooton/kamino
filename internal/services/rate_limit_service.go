package services

import (
	"context"
	"crypto/sha256"
	"fmt"
	"log/slog"
	"time"

	"github.com/BradenHooton/kamino/internal/models"
)

// RateLimitRepository defines the interface for rate limiting database operations
type RateLimitRepository interface {
	RecordAttempt(ctx context.Context, attempt *models.LoginAttempt) error
	GetFailedAttemptCount(ctx context.Context, email string, since time.Time) (int, error)
	GetRecentFailureTime(ctx context.Context, email string, since time.Time) (*time.Time, error)
	GetLastSuccessTime(ctx context.Context, email string) (*time.Time, error)
	GetFailedAttemptCountByIP(ctx context.Context, ipAddress string, since time.Time) (int, error)
	GetFailedAttemptCountByDevice(ctx context.Context, fingerprint string, since time.Time) (int, error)
}

// RateLimitConfig holds configuration for rate limiting behavior
type RateLimitConfig struct {
	MaxFailedAttemptsPerEmail  int
	EmailLockoutDuration       time.Duration
	MaxAttemptsPerIP           int
	MaxAttemptsPerDevice       int
	LookbackWindow             time.Duration
	ProgressiveLockoutMultiplier float64 // e.g., 1.5x for each lockout
	MaxLockoutDuration         time.Duration // Cap on lockout time
}

// RateLimitService implements rate limiting logic for authentication
type RateLimitService struct {
	repo   RateLimitRepository
	config RateLimitConfig
	logger *slog.Logger
}

// NewRateLimitService creates a new RateLimitService
func NewRateLimitService(repo RateLimitRepository, config RateLimitConfig, logger *slog.Logger) *RateLimitService {
	return &RateLimitService{
		repo:   repo,
		config: config,
		logger: logger,
	}
}

// CheckRateLimit checks if a login attempt should be allowed based on rate limiting rules
// Returns (allowed bool, lockoutDuration *time.Duration, err error)
// If allowed=false, lockoutDuration indicates how long the account is locked
func (s *RateLimitService) CheckRateLimit(ctx context.Context, email, ipAddress, userAgent string) (bool, *time.Duration, error) {
	deviceFingerprint := generateDeviceFingerprint(ipAddress, userAgent)
	lookbackTime := time.Now().Add(-s.config.LookbackWindow)

	// 1. Check account-based rate limiting
	failedCount, err := s.repo.GetFailedAttemptCount(ctx, email, lookbackTime)
	if err != nil {
		s.logger.Error("failed to check email rate limit", slog.Any("error", err))
		// Fail open for availability - DB errors shouldn't block legitimate users
		// Security decisions (rate limit exceeded) still fail closed
		return true, nil, nil
	}

	if failedCount >= s.config.MaxFailedAttemptsPerEmail {
		lockoutDuration := s.calculateLockoutDuration(email, lookbackTime)
		s.logger.Warn("account rate limited",
			slog.String("email", email),
			slog.Int("failed_attempts", failedCount),
			slog.Duration("lockout_duration", lockoutDuration))
		return false, &lockoutDuration, nil
	}

	// 2. Check IP-based rate limiting
	ipAttempts, err := s.repo.GetFailedAttemptCountByIP(ctx, ipAddress, lookbackTime)
	if err != nil {
		s.logger.Error("failed to check IP rate limit", slog.Any("error", err))
		return true, nil, nil
	}

	if ipAttempts >= s.config.MaxAttemptsPerIP {
		s.logger.Warn("IP rate limited",
			slog.String("ip_address", ipAddress),
			slog.Int("failed_attempts", ipAttempts))
		return false, nil, models.ErrRateLimitExceeded
	}

	// 3. Check device-based rate limiting
	deviceAttempts, err := s.repo.GetFailedAttemptCountByDevice(ctx, deviceFingerprint, lookbackTime)
	if err != nil {
		s.logger.Error("failed to check device rate limit", slog.Any("error", err))
		return true, nil, nil
	}

	if deviceAttempts >= s.config.MaxAttemptsPerDevice {
		s.logger.Warn("device rate limited",
			slog.String("device_fingerprint", deviceFingerprint),
			slog.Int("failed_attempts", deviceAttempts))
		return false, nil, models.ErrRateLimitExceeded
	}

	return true, nil, nil
}

// RecordLoginAttempt records the outcome of a login attempt
func (s *RateLimitService) RecordLoginAttempt(ctx context.Context, email, ipAddress, userAgent string, success bool, failureReason *string) error {
	deviceFingerprint := generateDeviceFingerprint(ipAddress, userAgent)
	expiresAt := time.Now().Add(s.config.LookbackWindow * 2) // Keep records for 2x lookback window

	attempt := &models.LoginAttempt{
		Email:             email,
		IPAddress:         ipAddress,
		UserAgent:         userAgent,
		Success:           success,
		FailureReason:     failureReason,
		DeviceFingerprint: deviceFingerprint,
		ExpiresAt:         expiresAt,
	}

	return s.repo.RecordAttempt(ctx, attempt)
}

// calculateLockoutDuration determines the lockout time based on failure patterns
// Uses progressive backoff: base → base*multiplier → base*multiplier^2, capped at max
func (s *RateLimitService) calculateLockoutDuration(email string, lookbackTime time.Time) time.Duration {
	baseLockout := s.config.EmailLockoutDuration

	// Simple progressive lockout: each set of max_attempts increases lockout by a factor
	// For now, use base lockout. In future: track # of lockouts and increase multiplier
	lockoutDuration := baseLockout

	if lockoutDuration > s.config.MaxLockoutDuration {
		lockoutDuration = s.config.MaxLockoutDuration
	}

	return lockoutDuration
}

// generateDeviceFingerprint creates a hash of IP + User-Agent for device identification
func generateDeviceFingerprint(ipAddress, userAgent string) string {
	data := []byte(fmt.Sprintf("%s:%s", ipAddress, userAgent))
	hash := sha256.Sum256(data)
	return fmt.Sprintf("%x", hash)[:32] // Use first 32 chars of hex hash
}
