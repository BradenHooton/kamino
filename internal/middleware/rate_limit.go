package middleware

import (
	"net/http"
	"time"

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
