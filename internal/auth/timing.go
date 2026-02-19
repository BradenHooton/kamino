package auth

import (
	"crypto/rand"
	"encoding/binary"
	"time"
)

// TimingConfig holds configuration for timing attack prevention
type TimingConfig struct {
	BaseDelayMs       int  // Base delay in milliseconds
	RandomDelayMs     int  // Random delay range in milliseconds
	DelayOnSuccess    bool // If true, delay even on successful login
}

// TimingDelay applies a constant-time delay to prevent timing attacks
// It ensures all authentication failures take approximately the same time
type TimingDelay struct {
	config TimingConfig
}

// NewTimingDelay creates a new TimingDelay instance
func NewTimingDelay(config TimingConfig) *TimingDelay {
	return &TimingDelay{
		config: config,
	}
}

// cryptoRandIntn returns a secure random number between 0 and max (exclusive)
// Uses crypto/rand instead of math/rand for security-sensitive operations
func cryptoRandIntn(max int) (int, error) {
	if max <= 0 {
		return 0, nil
	}

	// Generate random bytes
	randomBytes := make([]byte, 8)
	_, err := rand.Read(randomBytes)
	if err != nil {
		return 0, err
	}

	// Convert bytes to uint64 and modulo by max
	randomValue := binary.BigEndian.Uint64(randomBytes)
	return int(randomValue % uint64(max)), nil
}

// Wait applies the appropriate delay based on operation success/failure
// If success=false (or delayOnSuccess=true), waits for: baseDelay + randomDelay
// This ensures that "user not found" and "password incorrect" take similar time
func (td *TimingDelay) Wait(success bool) {
	// Only delay on failure, unless configured to delay on success too
	if success && !td.config.DelayOnSuccess {
		return
	}

	baseDelay := time.Duration(td.config.BaseDelayMs) * time.Millisecond
	var randomDelay time.Duration
	if td.config.RandomDelayMs > 0 {
		randomValue, err := cryptoRandIntn(td.config.RandomDelayMs)
		if err == nil {
			randomDelay = time.Duration(randomValue) * time.Millisecond
		}
	}
	totalDelay := baseDelay + randomDelay

	time.Sleep(totalDelay)
}

// WaitFrom applies delay relative to a start time, ensuring total elapsed time ≥ target
// Useful if some operations already consumed time
func (td *TimingDelay) WaitFrom(startTime time.Time, success bool) {
	if success && !td.config.DelayOnSuccess {
		return
	}

	baseDelay := time.Duration(td.config.BaseDelayMs) * time.Millisecond
	var randomDelay time.Duration
	if td.config.RandomDelayMs > 0 {
		randomValue, err := cryptoRandIntn(td.config.RandomDelayMs)
		if err == nil {
			randomDelay = time.Duration(randomValue) * time.Millisecond
		}
	}
	targetDelay := baseDelay + randomDelay

	elapsed := time.Since(startTime)
	if elapsed < targetDelay {
		time.Sleep(targetDelay - elapsed)
	}
}
