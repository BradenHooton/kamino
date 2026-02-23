package models

import (
	"time"
)

type User struct {
	ID                string
	Email             string
	PasswordHash      string // NULL for OAuth-only users
	Name              string
	EmailVerified     bool
	TokenKey          string // Per-user secret for composite token signing
	CreatedAt         time.Time
	UpdatedAt         time.Time
	Role              string     // e.g., "user", "admin"
	Status            string     // "active", "suspended", "disabled"
	LockedUntil       *time.Time // Temporary account lock expiration
	PasswordChangedAt *time.Time // Last password change timestamp for token invalidation
	MFAEnabled        bool
	MFAEnrolledAt     *time.Time // When user first successfully enrolled in MFA
}

// SearchCriteria holds optional filters for admin user search queries.
// All pointer fields are optional; only non-nil/non-empty values are applied.
type SearchCriteria struct {
	Email  *string // Trigram ILIKE match on email
	Name   *string // Trigram ILIKE match on name
	Role   *string // Exact match: "user" or "admin"
	Status *string // Exact match: "active", "suspended", or "disabled"
	Limit  int     // Default 20, max 100
	Offset int     // Default 0
}
