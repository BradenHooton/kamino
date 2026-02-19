package middleware

import (
	"log/slog"
	"net/http"

	"github.com/BradenHooton/kamino/internal/auth"
)

// CSRFProtection middleware validates CSRF tokens on state-changing requests
// Only applies to POST, PUT, DELETE, PATCH methods
// Extracts CSRF token from X-CSRF-Token header or cookie
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
			if userID == nil {
				// Not authenticated - CSRF protection only for authenticated users
				// Unauthenticated state-changing requests don't need CSRF protection
				next.ServeHTTP(w, r)
				return
			}

			// Extract CSRF token from header first, then cookie
			csrfToken := r.Header.Get("X-CSRF-Token")
			if csrfToken == "" {
				// Try to get from cookie
				if cookie, err := r.Cookie("csrf_token"); err == nil {
					csrfToken = cookie.Value
				}
			}

			if csrfToken == "" {
				logger.Warn("CSRF token missing in request",
					slog.String("method", r.Method),
					slog.String("path", r.RequestURI),
					slog.String("user_id", userID.UserID))
				http.Error(w, "CSRF token missing", http.StatusForbidden)
				return
			}

			// Validate CSRF token
			if !csrfManager.ValidateToken(csrfToken, userID.UserID) {
				logger.Warn("CSRF token validation failed",
					slog.String("method", r.Method),
					slog.String("path", r.RequestURI),
					slog.String("user_id", userID.UserID))
				http.Error(w, "CSRF token invalid", http.StatusForbidden)
				return
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
