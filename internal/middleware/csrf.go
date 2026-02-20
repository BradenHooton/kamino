package middleware

import (
	"log/slog"
	"net/http"

	"github.com/BradenHooton/kamino/internal/auth"
)

// CSRFProtection middleware validates CSRF tokens on state-changing requests
// Applies to ALL state-changing requests (POST, PUT, DELETE, PATCH):
// - Authenticated requests: require valid CSRF token
// - Public requests: require CSRF token (double-submit cookie pattern for public endpoints)
func CSRFProtection(csrfManager *auth.CSRFTokenManager, logger *slog.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Only protect state-changing methods
			if !isStateChangingMethod(r.Method) {
				next.ServeHTTP(w, r)
				return
			}

			// Extract user ID from context (set by auth middleware)
			userID := auth.GetUserFromContext(r)

			// Extract CSRF token from header first, then cookie (for all requests)
			csrfToken := r.Header.Get("X-CSRF-Token")
			if csrfToken == "" {
				// Try to get from cookie
				if cookie, err := r.Cookie("csrf_token"); err == nil {
					csrfToken = cookie.Value
				}
			}

			if csrfToken == "" {
				if userID != nil {
					logger.Warn("CSRF token missing in request",
						slog.String("method", r.Method),
						slog.String("path", r.RequestURI),
						slog.String("user_id", userID.UserID))
				} else {
					logger.Warn("CSRF token missing in request (public endpoint)",
						slog.String("method", r.Method),
						slog.String("path", r.RequestURI))
				}
				http.Error(w, "CSRF token missing", http.StatusForbidden)
				return
			}

			// For authenticated requests, validate CSRF token against user ID
			if userID != nil {
				if !csrfManager.ValidateToken(csrfToken, userID.UserID) {
					logger.Warn("CSRF token validation failed",
						slog.String("method", r.Method),
						slog.String("path", r.RequestURI),
						slog.String("user_id", userID.UserID))
					http.Error(w, "CSRF token invalid", http.StatusForbidden)
					return
				}
			} else {
				// For unauthenticated requests (public endpoints), use double-submit cookie validation
				// Verify that the token matches the CSRF cookie value
				csrfCookie, err := r.Cookie("csrf_token")
				if err != nil || csrfCookie.Value != csrfToken {
					logger.Warn("CSRF token validation failed for public endpoint",
						slog.String("method", r.Method),
						slog.String("path", r.RequestURI))
					http.Error(w, "CSRF token invalid", http.StatusForbidden)
					return
				}
			}

			// CSRF token valid, continue
			next.ServeHTTP(w, r)
		})
	}
}

// isStateChangingMethod checks if the HTTP method modifies state
func isStateChangingMethod(method string) bool {
	switch method {
	case http.MethodPost, http.MethodPut, http.MethodDelete, http.MethodPatch:
		return true
	default:
		return false
	}
}
