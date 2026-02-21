package middleware

import (
	"net/http"
	"time"

	"github.com/BradenHooton/kamino/internal/auth"
	"github.com/go-chi/httprate"
)

// RateLimitConfig holds rate limiting configuration
type RateLimitConfig struct {
	RequestsPerMinute int
}

// DefaultAuthRateLimit returns default rate limit config for auth endpoints (5 requests per minute)
func DefaultAuthRateLimit() RateLimitConfig {
	return RateLimitConfig{
		RequestsPerMinute: 5,
	}
}

// RateLimitByIP creates a middleware that rate limits requests by client IP
func RateLimitByIP(config RateLimitConfig) func(next http.Handler) http.Handler {
	return httprate.Limit(
		config.RequestsPerMinute,
		1*time.Minute,
		httprate.WithKeyByRealIP(),
		httprate.WithLimitHandler(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusTooManyRequests)
			w.Write([]byte(`{"error":"Rate limit exceeded"}`))
		}),
	)
}

// AuthenticatedRateLimitConfig holds rate limiting configuration for authenticated endpoints
type AuthenticatedRateLimitConfig struct {
	ReadOperationsPerMinute  int // Default: 100
	WriteOperationsPerMinute int // Default: 30
	AdminOperationsPerMinute int // Default: 60
}

// DefaultAuthenticatedRateLimits returns default rate limit config
func DefaultAuthenticatedRateLimits() AuthenticatedRateLimitConfig {
	return AuthenticatedRateLimitConfig{
		ReadOperationsPerMinute:  100,
		WriteOperationsPerMinute: 30,
		AdminOperationsPerMinute: 60,
	}
}

// extractUserOrAPIKeyID extracts user ID from context for rate limiting
// Works for both JWT tokens and API keys
// Returns empty string if no user context (fallback to IP-based)
func extractUserOrAPIKeyID(r *http.Request) string {
	claims := auth.GetUserFromContext(r)
	if claims == nil {
		return "" // Fallback to IP-based
	}
	return claims.UserID // Works for both JWT and API keys
}

// RateLimitByUserID creates a middleware that rate limits requests by authenticated user ID
// Falls back to IP-based rate limiting if user context unavailable
// operationType should be "read", "write", or "admin"
func RateLimitByUserID(config AuthenticatedRateLimitConfig, operationType string) func(next http.Handler) http.Handler {
	var limit int
	switch operationType {
	case "read":
		limit = config.ReadOperationsPerMinute
	case "write":
		limit = config.WriteOperationsPerMinute
	case "admin":
		limit = config.AdminOperationsPerMinute
	default:
		limit = 60 // Fallback
	}

	keyFunc := func(r *http.Request) (string, error) {
		userID := extractUserOrAPIKeyID(r)
		if userID == "" {
			// Fallback to IP-based if no user context
			return r.RemoteAddr, nil
		}
		return "user:" + userID, nil
	}

	return httprate.Limit(
		limit,
		time.Minute,
		httprate.WithKeyFuncs(keyFunc),
		httprate.WithLimitHandler(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusTooManyRequests)
			w.Write([]byte(`{"error":"rate_limit_exceeded","message":"Too many requests"}`))
		}),
	)
}
