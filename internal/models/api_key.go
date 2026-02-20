package models

import (
	"regexp"
	"time"
)

// APIKey represents an API key for service account authentication
type APIKey struct {
	ID        string     `json:"id"`
	UserID    string     `json:"user_id"`
	KeyHash   string     `json:"-"` // Never exposed
	KeyPrefix string     `json:"key_prefix"`
	Name      string     `json:"name"`
	Scopes    []string   `json:"scopes"`
	LastUsedAt *time.Time `json:"last_used_at,omitempty"`
	ExpiresAt *time.Time `json:"expires_at,omitempty"`
	RevokedAt *time.Time `json:"revoked_at,omitempty"`
	CreatedAt time.Time  `json:"created_at"`
	UpdatedAt time.Time  `json:"updated_at"`
}

// GeneratedAPIKey represents the response when creating a new API key (includes plaintext)
type GeneratedAPIKey struct {
	PlainKey string  `json:"key"` // Shown ONLY once at creation
	APIKey   *APIKey `json:"api_key"`
}

// IsActive returns true if the API key is valid for use
func (k *APIKey) IsActive() bool {
	if k.RevokedAt != nil {
		return false
	}
	if k.ExpiresAt != nil && time.Now().After(*k.ExpiresAt) {
		return false
	}
	return true
}

// IsExpired returns true if the API key has expired
func (k *APIKey) IsExpired() bool {
	if k.ExpiresAt != nil && time.Now().After(*k.ExpiresAt) {
		return true
	}
	return false
}

// HasScope returns true if the API key has the specified scope
func (k *APIKey) HasScope(scope string) bool {
	for _, s := range k.Scopes {
		if s == scope {
			return true
		}
	}
	return false
}

// ValidateScopes returns an error if scopes are invalid
// Validates against whitelist and enforces "resource.action" format
func ValidateScopes(scopes []string) error {
	if len(scopes) == 0 {
		return ErrBadRequest // Scopes cannot be empty
	}

	for _, scope := range scopes {
		// Check whitelist first
		if !IsValidScope(scope) {
			return ErrBadRequest // Invalid scope not in whitelist
		}

		// Wildcard "*" is valid but has special meaning (admin only)
		if scope == ScopeAll {
			continue
		}

		// Enforce "resource.action" format for non-wildcard scopes
		// Valid patterns: users.read, users.write, api_keys.create, etc.
		if !regexp.MustCompile(`^[a-z_]+\.(read|write|delete|create|revoke)$`).MatchString(scope) {
			return ErrBadRequest // Invalid scope format
		}
	}
	return nil
}
