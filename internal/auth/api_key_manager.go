package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
)

// APIKeyManager handles API key generation, hashing, and validation
type APIKeyManager struct {
	prefix string // Usually "kmn_"
}

// NewAPIKeyManager creates a new APIKeyManager
func NewAPIKeyManager() *APIKeyManager {
	return &APIKeyManager{
		prefix: "kmn_",
	}
}

// GenerateAPIKey generates a new API key in the format: kmn_<64 hex chars>
// Returns plaintext key (shown once to user) and SHA256 hash (stored in DB)
func (m *APIKeyManager) GenerateAPIKey() (plainKey, hash string, err error) {
	// Generate 32 random bytes (256 bits of entropy = 64 hex chars)
	randomBytes := make([]byte, 32)
	if _, err := rand.Read(randomBytes); err != nil {
		return "", "", fmt.Errorf("failed to generate random bytes: %w", err)
	}

	// Create plaintext key: kmn_<64 hex chars>
	hexPart := hex.EncodeToString(randomBytes)
	plainKey = m.prefix + hexPart // 4 + 64 = 68 chars total

	// Hash the plaintext key with SHA256
	hashBytes := sha256.Sum256([]byte(plainKey))
	hash = hex.EncodeToString(hashBytes[:])

	return plainKey, hash, nil
}

// HashAPIKey hashes an existing API key
func (m *APIKeyManager) HashAPIKey(plainKey string) (string, error) {
	if !strings.HasPrefix(plainKey, m.prefix) || len(plainKey) != len(m.prefix)+64 {
		return "", errors.New("invalid API key format")
	}
	hashBytes := sha256.Sum256([]byte(plainKey))
	return hex.EncodeToString(hashBytes[:]), nil
}

// ValidateAndHashAPIKey validates the format and returns the hash
func (m *APIKeyManager) ValidateAndHashAPIKey(plainKey string) (string, error) {
	if !strings.HasPrefix(plainKey, m.prefix) {
		return "", errors.New("invalid API key format: missing prefix")
	}
	if len(plainKey) != len(m.prefix)+64 {
		return "", fmt.Errorf("invalid API key format: expected %d chars, got %d", len(m.prefix)+64, len(plainKey))
	}
	return m.HashAPIKey(plainKey)
}

// GetKeyPrefix returns the first 12 characters of the key (for display)
func (m *APIKeyManager) GetKeyPrefix(plainKey string) (string, error) {
	if len(plainKey) < 12 {
		return "", errors.New("API key too short")
	}
	return plainKey[:12], nil
}

// ConstantTimeHashCompare compares two SHA256 hashes with constant-time comparison
// Returns true if hashes match, false otherwise
func ConstantTimeHashCompare(hash1, hash2 string) bool {
	return subtle.ConstantTimeCompare([]byte(hash1), []byte(hash2)) == 1
}
