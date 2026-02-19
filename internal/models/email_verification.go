package models

import (
	"time"
)

// EmailVerificationToken represents an email verification token
type EmailVerificationToken struct {
	ID        string    `json:"id"`
	UserID    string    `json:"user_id"`
	TokenHash string    `json:"-"` // Never expose token hash
	Email     string    `json:"email"`
	ExpiresAt time.Time `json:"expires_at"`
	UsedAt    *time.Time `json:"used_at,omitempty"`
	CreatedAt time.Time `json:"created_at"`
}

// IsExpired checks if the token has expired
func (t *EmailVerificationToken) IsExpired() bool {
	return time.Now().After(t.ExpiresAt)
}

// IsUsed checks if the token has already been used
func (t *EmailVerificationToken) IsUsed() bool {
	return t.UsedAt != nil
}

// IsValid checks if the token is still valid (not expired and not used)
func (t *EmailVerificationToken) IsValid() bool {
	return !t.IsExpired() && !t.IsUsed()
}
