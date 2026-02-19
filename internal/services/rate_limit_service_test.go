package services_test

import (
	"context"
	"log/slog"
	"os"
	"testing"
	"time"

	"github.com/BradenHooton/kamino/internal/models"
	"github.com/BradenHooton/kamino/internal/services"
	"github.com/stretchr/testify/assert"
)

// MockRateLimitRepository implements RateLimitRepository for testing
type MockRateLimitRepository struct {
	attempts map[string]int
}

func NewMockRateLimitRepository() *MockRateLimitRepository {
	return &MockRateLimitRepository{
		attempts: make(map[string]int),
	}
}

func (m *MockRateLimitRepository) RecordAttempt(ctx context.Context, attempt *models.LoginAttempt) error {
	key := attempt.Email + "|" + attempt.IPAddress
	if !attempt.Success {
		m.attempts[key]++
	}
	return nil
}

func (m *MockRateLimitRepository) GetFailedAttemptCount(ctx context.Context, email string, since time.Time) (int, error) {
	count := 0
	for key, c := range m.attempts {
		if len(key) > 0 && key[:len(email)] == email {
			count = c
			break
		}
	}
	return count, nil
}

func (m *MockRateLimitRepository) GetRecentFailureTime(ctx context.Context, email string, since time.Time) (*time.Time, error) {
	now := time.Now()
	return &now, nil
}

func (m *MockRateLimitRepository) GetLastSuccessTime(ctx context.Context, email string) (*time.Time, error) {
	return nil, nil
}

func (m *MockRateLimitRepository) GetFailedAttemptCountByIP(ctx context.Context, ipAddress string, since time.Time) (int, error) {
	return 0, nil
}

func (m *MockRateLimitRepository) GetFailedAttemptCountByDevice(ctx context.Context, fingerprint string, since time.Time) (int, error) {
	return 0, nil
}

func TestRateLimitServiceCheckRateLimit_AllowsInitialAttempt(t *testing.T) {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	repo := NewMockRateLimitRepository()

	config := services.RateLimitConfig{
		MaxFailedAttemptsPerEmail:   5,
		EmailLockoutDuration:        15 * time.Minute,
		MaxAttemptsPerIP:            20,
		MaxAttemptsPerDevice:        10,
		LookbackWindow:              15 * time.Minute,
		ProgressiveLockoutMultiplier: 1.5,
		MaxLockoutDuration:          1 * time.Hour,
	}

	service := services.NewRateLimitService(repo, config, logger)
	ctx := context.Background()

	allowed, lockoutDuration, err := service.CheckRateLimit(ctx, "test@example.com", "192.168.1.1", "Mozilla/5.0")

	assert.NoError(t, err)
	assert.True(t, allowed)
	assert.Nil(t, lockoutDuration)
}

func TestRateLimitServiceCheckRateLimit_BlocksAfterMaxFailed(t *testing.T) {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	repo := NewMockRateLimitRepository()

	// Simulate 5 failed attempts
	for i := 0; i < 5; i++ {
		_ = repo.RecordAttempt(context.Background(), &models.LoginAttempt{
			Email:     "test@example.com",
			IPAddress: "192.168.1.1",
			Success:   false,
			ExpiresAt: time.Now().Add(15 * time.Minute),
		})
	}

	config := services.RateLimitConfig{
		MaxFailedAttemptsPerEmail:   5,
		EmailLockoutDuration:        15 * time.Minute,
		MaxAttemptsPerIP:            20,
		MaxAttemptsPerDevice:        10,
		LookbackWindow:              15 * time.Minute,
		ProgressiveLockoutMultiplier: 1.5,
		MaxLockoutDuration:          1 * time.Hour,
	}

	service := services.NewRateLimitService(repo, config, logger)
	ctx := context.Background()

	allowed, lockoutDuration, err := service.CheckRateLimit(ctx, "test@example.com", "192.168.1.1", "Mozilla/5.0")

	assert.NoError(t, err)
	assert.False(t, allowed)
	assert.NotNil(t, lockoutDuration)
	assert.Equal(t, 15*time.Minute, *lockoutDuration)
}

func TestRateLimitServiceRecordLoginAttempt_Success(t *testing.T) {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	repo := NewMockRateLimitRepository()

	config := services.RateLimitConfig{
		MaxFailedAttemptsPerEmail:   5,
		EmailLockoutDuration:        15 * time.Minute,
		MaxAttemptsPerIP:            20,
		MaxAttemptsPerDevice:        10,
		LookbackWindow:              15 * time.Minute,
		ProgressiveLockoutMultiplier: 1.5,
		MaxLockoutDuration:          1 * time.Hour,
	}

	service := services.NewRateLimitService(repo, config, logger)
	ctx := context.Background()

	err := service.RecordLoginAttempt(ctx, "test@example.com", "192.168.1.1", "Mozilla/5.0", true, nil)

	assert.NoError(t, err)
}

func TestRateLimitServiceRecordLoginAttempt_Failure(t *testing.T) {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	repo := NewMockRateLimitRepository()

	config := services.RateLimitConfig{
		MaxFailedAttemptsPerEmail:   5,
		EmailLockoutDuration:        15 * time.Minute,
		MaxAttemptsPerIP:            20,
		MaxAttemptsPerDevice:        10,
		LookbackWindow:              15 * time.Minute,
		ProgressiveLockoutMultiplier: 1.5,
		MaxLockoutDuration:          1 * time.Hour,
	}

	service := services.NewRateLimitService(repo, config, logger)
	ctx := context.Background()

	failureReason := "invalid_password"
	err := service.RecordLoginAttempt(ctx, "test@example.com", "192.168.1.1", "Mozilla/5.0", false, &failureReason)

	assert.NoError(t, err)
	assert.Equal(t, 1, repo.attempts["test@example.com|192.168.1.1"])
}
