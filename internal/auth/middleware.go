package auth

import (
	"context"
	"errors"
	"net/http"
	"strings"

	"github.com/BradenHooton/kamino/internal/models"
)

// contextKey is a custom type for context keys
type contextKey string

const (
	// UserContextKey is the key for storing user claims in context
	UserContextKey contextKey = "user"
)

// TokenRevocationChecker defines the interface for checking if tokens are revoked
type TokenRevocationChecker interface {
	IsTokenRevoked(ctx context.Context, jti string) (bool, error)
}

// RevocationConfig holds configuration for token revocation behavior
type RevocationConfig struct {
	FailClosed bool // If true, deny access if revocation check fails; if false, allow access (fail open)
}

// AuthMiddleware validates JWT tokens and injects user claims into context
func AuthMiddleware(tm *TokenManager) func(next http.Handler) http.Handler {
	return AuthMiddlewareWithRevocation(tm, nil, RevocationConfig{FailClosed: false})
}

// AuthMiddlewareWithRevocation validates JWT tokens and checks revocation status
// Supports configurable fail-closed behavior for revocation check failures
func AuthMiddlewareWithRevocation(tm *TokenManager, revocationChecker TokenRevocationChecker, revocationConfig RevocationConfig) func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Extract token from Authorization header
			authHeader := r.Header.Get("Authorization")
			if authHeader == "" {
				http.Error(w, "missing authorization header", http.StatusUnauthorized)
				return
			}

			// Parse Bearer token
			parts := strings.SplitN(authHeader, " ", 2)
			if len(parts) != 2 || parts[0] != "Bearer" {
				http.Error(w, "invalid authorization header format", http.StatusUnauthorized)
				return
			}

			tokenString := parts[1]

			// Validate token
			claims, err := tm.ValidateToken(tokenString)
			if err != nil {
				http.Error(w, "invalid or expired token", http.StatusUnauthorized)
				return
			}

			// Reject refresh tokens for API access (they should only be used with /auth/refresh)
			if claims.Type == "refresh" {
				http.Error(w, "refresh tokens cannot be used for API access", http.StatusUnauthorized)
				return
			}

			// Check if token is revoked (if revocation checker is available)
			if revocationChecker != nil && claims.ID != "" {
				revoked, err := revocationChecker.IsTokenRevoked(r.Context(), claims.ID)
				if err != nil {
					// Handle revocation check errors based on configuration
					if revocationConfig.FailClosed {
						// Fail closed: deny access if we can't verify revocation status
						http.Error(w, "unable to verify token status", http.StatusServiceUnavailable)
						return
					}
					// Fail open: allow access if revocation check fails (for availability)
					// Invalid/expired tokens still fail closed (handled above)
				}
				if revoked {
					http.Error(w, "token has been revoked", http.StatusUnauthorized)
					return
				}
			}

			// Inject claims into context
			ctx := context.WithValue(r.Context(), UserContextKey, claims)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// RequireRole creates a middleware that enforces role-based access control
func RequireRole(userRepo UserRepository, role string) func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Get user claims from context (must be used after AuthMiddleware)
			claims := GetUserFromContext(r)
			if claims == nil {
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}

			// Fetch user from database to get current role
			user, err := userRepo.GetByID(r.Context(), claims.UserID)
			if err != nil {
				if errors.Is(err, models.ErrNotFound) {
					http.Error(w, "user not found", http.StatusUnauthorized)
					return
				}
				http.Error(w, "internal server error", http.StatusInternalServerError)
				return
			}

			// Check if user has required role
			if user.Role != role {
				http.Error(w, "forbidden: insufficient permissions", http.StatusForbidden)
				return
			}

			// Proceed to next handler
			next.ServeHTTP(w, r)
		})
	}
}

// GetUserFromContext extracts user claims from request context
func GetUserFromContext(r *http.Request) *models.TokenClaims {
	claims, ok := r.Context().Value(UserContextKey).(*models.TokenClaims)
	if !ok {
		return nil
	}
	return claims
}

// UserRepository interface for fetching user data (reuse existing interface)
type UserRepository interface {
	GetByID(ctx context.Context, id string) (*models.User, error)
}
