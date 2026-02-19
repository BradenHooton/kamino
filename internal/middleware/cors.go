package middleware

import (
	"net/http"
	"strings"
)

// CORSConfig holds CORS configuration
type CORSConfig struct {
	AllowedOrigins  []string
	AllowedMethods  []string
	AllowedHeaders  []string
	ExposedHeaders  []string
	AllowCredentials bool
	MaxAge          int
}

// DefaultCORSConfig returns CORS configuration based on environment
func DefaultCORSConfig(env string) *CORSConfig {
	if env == "production" {
		return &CORSConfig{
			AllowedOrigins:  []string{}, // Should be populated from config
			AllowedMethods:  []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
			AllowedHeaders:  []string{"Content-Type", "Authorization"},
			ExposedHeaders:  []string{"Content-Length", "Authorization"},
			AllowCredentials: true,
			MaxAge:          3600,
		}
	}

	// Development: more permissive
	return &CORSConfig{
		AllowedOrigins:  []string{},
		AllowedMethods:  []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
		AllowedHeaders:  []string{"Content-Type", "Authorization"},
		ExposedHeaders:  []string{"Content-Length", "Authorization"},
		AllowCredentials: true,
		MaxAge:          3600,
	}
}

// CORS returns a CORS middleware handler
func CORS(config *CORSConfig) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			origin := r.Header.Get("Origin")

			// Check if origin is allowed
			allowed := false
			if origin != "" {
				for _, allowedOrigin := range config.AllowedOrigins {
					if origin == allowedOrigin {
						allowed = true
						break
					}
				}
			}

			// Security fail-closed: Only allow explicitly configured origins
			// This prevents accidental CORS misconfiguration in production
			if allowed {
				w.Header().Set("Access-Control-Allow-Origin", origin)
				w.Header().Set("Access-Control-Allow-Methods", strings.Join(config.AllowedMethods, ", "))
				w.Header().Set("Access-Control-Allow-Headers", strings.Join(config.AllowedHeaders, ", "))
				w.Header().Set("Access-Control-Expose-Headers", strings.Join(config.ExposedHeaders, ", "))
				if config.AllowCredentials {
					w.Header().Set("Access-Control-Allow-Credentials", "true")
				}
				w.Header().Set("Access-Control-Max-Age", "3600")
			}

			// Handle preflight requests
			if r.Method == http.MethodOptions {
				w.WriteHeader(http.StatusOK)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}
