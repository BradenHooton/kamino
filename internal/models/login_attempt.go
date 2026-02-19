package models

import "time"

// LoginAttempt represents a single login attempt in the system
type LoginAttempt struct {
	ID                string     `db:"id"`
	Email             string     `db:"email"`
	IPAddress         string     `db:"ip_address"`
	UserAgent         string     `db:"user_agent"`
	AttemptTime       time.Time  `db:"attempt_time"`
	Success           bool       `db:"success"`
	FailureReason     *string    `db:"failure_reason"`
	DeviceFingerprint string     `db:"device_fingerprint"`
	ExpiresAt         time.Time  `db:"expires_at"`
}

// LoginAttemptStats aggregates login attempt statistics for rate limiting decisions
type LoginAttemptStats struct {
	Email              string
	TotalFailedCount   int       // Failed attempts in lookback window
	RecentFailureTime  *time.Time // Most recent failure timestamp
	LastSuccessTime    *time.Time // Last successful login
	IsLocked           bool      // Account is temporarily locked
	LockedUntil        *time.Time // When the lock expires
	DeviceFingerprint  string
	IPAddress          string
}
