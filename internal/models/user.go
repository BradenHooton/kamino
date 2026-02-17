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
	Role 		string // e.g., "user", "admin"
    Status            string     // "active", "suspended", "disabled"
    LockedUntil       *time.Time // Temporary account lock expiration
    PasswordChangedAt *time.Time // Last password change timestamp for token invalidation
}