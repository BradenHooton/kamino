package auth

import (
	"crypto/rand"
	"encoding/hex"
	"sync"
	"time"
)

// csrfTokenEntry stores token metadata
type csrfTokenEntry struct {
	userID string
	expiry time.Time
}

// CSRFTokenManager handles CSRF token generation and validation
type CSRFTokenManager struct {
	validTokens map[string]*csrfTokenEntry // token -> entry (userID + expiry)
	mu          sync.RWMutex
	tokenTTL    time.Duration
}

// NewCSRFTokenManager creates a new CSRF token manager
func NewCSRFTokenManager() *CSRFTokenManager {
	manager := &CSRFTokenManager{
		validTokens: make(map[string]*csrfTokenEntry),
		tokenTTL:    15 * time.Minute, // CSRF tokens valid for 15 minutes
	}

	// Start cleanup goroutine to remove expired tokens
	go manager.cleanupExpiredTokens()

	return manager
}

// GenerateToken creates a new CSRF token for a specific user
func (m *CSRFTokenManager) GenerateToken(userID string) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Generate 32 random bytes
	randomBytes := make([]byte, 32)
	_, err := rand.Read(randomBytes)
	if err != nil {
		return "", err
	}

	token := hex.EncodeToString(randomBytes)
	m.validTokens[token] = &csrfTokenEntry{
		userID: userID,
		expiry: time.Now().Add(m.tokenTTL),
	}

	return token, nil
}

// ValidateToken checks if a CSRF token is valid and belongs to the user
func (m *CSRFTokenManager) ValidateToken(token, userID string) bool {
	m.mu.RLock()
	entry, exists := m.validTokens[token]
	m.mu.RUnlock()

	if !exists {
		return false
	}

	// Verify token belongs to this user
	if entry.userID != userID {
		return false
	}

	if time.Now().After(entry.expiry) {
		// Token is expired, remove it
		m.mu.Lock()
		delete(m.validTokens, token)
		m.mu.Unlock()
		return false
	}

	return true
}

// RevokeToken invalidates a CSRF token (used after a state-changing request)
func (m *CSRFTokenManager) RevokeToken(token string) {
	m.mu.Lock()
	delete(m.validTokens, token)
	m.mu.Unlock()
}

// cleanupExpiredTokens periodically removes expired tokens
func (m *CSRFTokenManager) cleanupExpiredTokens() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for range ticker.C {
		m.mu.Lock()
		now := time.Now()
		for token, entry := range m.validTokens {
			if now.After(entry.expiry) {
				delete(m.validTokens, token)
			}
		}
		m.mu.Unlock()
	}
}
