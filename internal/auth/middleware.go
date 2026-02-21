package auth

import (
	"context"
	"errors"
	"net/http"
	"strings"

	"github.com/BradenHooton/kamino/internal/models"
	pkghttp "github.com/BradenHooton/kamino/pkg/http"
)

// contextKey is a custom type for context keys
type contextKey string

const (
	// UserContextKey is the key for storing user claims in context
	UserContextKey contextKey = "user"
	// TokenContextKey is the key for storing the raw JWT token string in context
	TokenContextKey contextKey = "token"
	// APIKeyContextKey is the key for storing API key information in context
	APIKeyContextKey contextKey = "api_key"
	// RequiredScopesContextKey is the key for storing required scopes in context
	RequiredScopesContextKey contextKey = "required_scopes"
	// APIKeyPrefixContextKey is the key for storing the API key prefix for audit logging
	APIKeyPrefixContextKey contextKey = "api_key_prefix"
	// EndpointContextKey is the key for storing the request endpoint for audit logging
	EndpointContextKey contextKey = "endpoint"
)

// responseWriterWithStatus wraps http.ResponseWriter to capture HTTP status codes
type responseWriterWithStatus struct {
	http.ResponseWriter
	statusCode int
	written    bool
}

// WriteHeader captures the HTTP status code before delegating to the wrapped ResponseWriter
func (rw *responseWriterWithStatus) WriteHeader(code int) {
	if !rw.written {
		rw.statusCode = code
		rw.written = true
	}
	rw.ResponseWriter.WriteHeader(code)
}

// Write ensures WriteHeader is called before writing (for default 200 status)
func (rw *responseWriterWithStatus) Write(b []byte) (int, error) {
	if !rw.written {
		rw.statusCode = http.StatusOK
		rw.written = true
	}
	return rw.ResponseWriter.Write(b)
}

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
				pkghttp.WriteUnauthorized(w, "missing authorization header")
				return
			}

			// Parse Bearer token
			parts := strings.SplitN(authHeader, " ", 2)
			if len(parts) != 2 || parts[0] != "Bearer" {
				pkghttp.WriteUnauthorized(w, "invalid authorization header format")
				return
			}

			tokenString := parts[1]

			// Validate token
			claims, err := tm.ValidateToken(tokenString)
			if err != nil {
				pkghttp.WriteUnauthorized(w, "invalid or expired token")
				return
			}

			// Reject refresh tokens for API access (they should only be used with /auth/refresh)
			if claims.Type == "refresh" {
				pkghttp.WriteUnauthorized(w, "refresh tokens cannot be used for API access")
				return
			}

			// Check if token is revoked (if revocation checker is available)
			if revocationChecker != nil && claims.ID != "" {
				revoked, err := revocationChecker.IsTokenRevoked(r.Context(), claims.ID)
				if err != nil {
					// Handle revocation check errors based on configuration
					if revocationConfig.FailClosed {
						// Fail closed: deny access if we can't verify revocation status
						pkghttp.WriteError(w, http.StatusServiceUnavailable, "service_unavailable", "unable to verify token status")
						return
					}
					// Fail open: allow access if revocation check fails (for availability)
					// Invalid/expired tokens still fail closed (handled above)
				}
				if revoked {
					pkghttp.WriteUnauthorized(w, "token has been revoked")
					return
				}
			}

			// Inject claims and token into context
			ctx := context.WithValue(r.Context(), UserContextKey, claims)
			ctx = context.WithValue(ctx, TokenContextKey, tokenString)
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
				pkghttp.WriteUnauthorized(w, "unauthorized")
				return
			}

			// Fetch user from database to get current role
			user, err := userRepo.GetByID(r.Context(), claims.UserID)
			if err != nil {
				if errors.Is(err, models.ErrNotFound) {
					pkghttp.WriteUnauthorized(w, "user not found")
					return
				}
				pkghttp.WriteInternalError(w, "internal server error")
				return
			}

			// Check if user has required role
			if user.Role != role {
				pkghttp.WriteForbidden(w, "forbidden: insufficient permissions")
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

// GetTokenFromContext extracts the raw JWT token string from request context
// This token was validated and added to context by AuthMiddleware
func GetTokenFromContext(r *http.Request) string {
	token, _ := r.Context().Value(TokenContextKey).(string)
	return token
}

// GetRequiredScopesFromContext extracts required scopes from request context
func GetRequiredScopesFromContext(r *http.Request) []string {
	scopes, _ := r.Context().Value(RequiredScopesContextKey).([]string)
	return scopes
}

// GetAPIKeyPrefixFromContext extracts the API key prefix from request context
func GetAPIKeyPrefixFromContext(r *http.Request) string {
	prefix, _ := r.Context().Value(APIKeyPrefixContextKey).(string)
	return prefix
}

// GetEndpointFromContext extracts the endpoint from request context
func GetEndpointFromContext(r *http.Request) string {
	endpoint, _ := r.Context().Value(EndpointContextKey).(string)
	return endpoint
}

// APIKeyValidator defines the interface for validating API keys
type APIKeyValidator interface {
	ValidateAPIKey(ctx context.Context, plainKey string) (*models.APIKey, error)
}

// AuditLogger defines the interface for logging audit events
type AuditLogger interface {
	LogAPIKeyUsage(
		ctx context.Context,
		actorID string, // User ID
		keyID string,
		keyPrefix string,
		endpoint string,
		method string,
		requiredScopes []string,
		statusCode int,
		ipAddress *string,
		userAgent *string,
	)
}

// AuthMiddlewareWithAPIKey validates either X-API-Key header OR JWT Bearer token
// X-API-Key is checked FIRST (takes precedence), then falls back to Bearer token
// Creates pseudo-claims for API keys to maintain consistent context usage
// Optional AuditLogger can be provided to log API key usage
func AuthMiddlewareWithAPIKey(tm *TokenManager, apiKeyValidator APIKeyValidator, revocationChecker TokenRevocationChecker, revocationConfig RevocationConfig, auditLogger AuditLogger, ipConfig *pkghttp.IPConfig) func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Check for X-API-Key header FIRST (takes precedence)
			if apiKey := r.Header.Get("X-API-Key"); apiKey != "" {
				// Validate API key
				apiKeyObj, err := apiKeyValidator.ValidateAPIKey(r.Context(), apiKey)
				if err != nil {
					pkghttp.WriteUnauthorized(w, "invalid or expired api key")
					return
				}

				// Create pseudo-claims for API key
				claims := &models.TokenClaims{
					Type:   "api_key",
					UserID: apiKeyObj.UserID,
					Email:  "", // Not typically available from API key
					Scopes: apiKeyObj.Scopes,
				}

				// Extract client IP (with trusted proxy validation) and user agent for audit logging
				clientIP := pkghttp.ExtractClientIP(r, ipConfig)
				userAgent := r.Header.Get("User-Agent")

				// Wrap response writer to capture status code if audit logging is enabled
				var wrappedWriter http.ResponseWriter = w
				var statusCapture *responseWriterWithStatus
				if auditLogger != nil {
					statusCapture = &responseWriterWithStatus{ResponseWriter: w, statusCode: http.StatusOK}
					wrappedWriter = statusCapture
				}

				// Inject claims into context
				ctx := context.WithValue(r.Context(), UserContextKey, claims)
				ctx = context.WithValue(ctx, APIKeyContextKey, apiKeyObj)
				ctx = context.WithValue(ctx, APIKeyPrefixContextKey, apiKeyObj.KeyPrefix)
				ctx = context.WithValue(ctx, EndpointContextKey, r.RequestURI)

				// Use defer to log API key usage AFTER request completes
				if auditLogger != nil {
					defer func() {
						ipPtr := &clientIP
						userAgentPtr := &userAgent
						auditLogger.LogAPIKeyUsage(
							r.Context(),
							apiKeyObj.UserID,
							apiKeyObj.ID,
							apiKeyObj.KeyPrefix,
							r.RequestURI,
							r.Method,
							claims.Scopes,
							statusCapture.statusCode,
							ipPtr,
							userAgentPtr,
						)
					}()
				}

				next.ServeHTTP(wrappedWriter, r.WithContext(ctx))
				return
			}

			// Fall back to Bearer token authentication
			authHeader := r.Header.Get("Authorization")
			if authHeader == "" {
				pkghttp.WriteUnauthorized(w, "missing authorization header")
				return
			}

			// Parse Bearer token
			parts := strings.SplitN(authHeader, " ", 2)
			if len(parts) != 2 || parts[0] != "Bearer" {
				pkghttp.WriteUnauthorized(w, "invalid authorization header format")
				return
			}

			tokenString := parts[1]

			// Validate token
			claims, err := tm.ValidateToken(tokenString)
			if err != nil {
				pkghttp.WriteUnauthorized(w, "invalid or expired token")
				return
			}

			// Reject refresh tokens for API access
			if claims.Type == "refresh" {
				pkghttp.WriteUnauthorized(w, "refresh tokens cannot be used for API access")
				return
			}

			// Check if token is revoked (if revocation checker is available)
			if revocationChecker != nil && claims.ID != "" {
				revoked, err := revocationChecker.IsTokenRevoked(r.Context(), claims.ID)
				if err != nil {
					if revocationConfig.FailClosed {
						pkghttp.WriteError(w, http.StatusServiceUnavailable, "service_unavailable", "unable to verify token status")
						return
					}
				}
				if revoked {
					pkghttp.WriteUnauthorized(w, "token has been revoked")
					return
				}
			}

			// Inject claims and token into context
			ctx := context.WithValue(r.Context(), UserContextKey, claims)
			ctx = context.WithValue(ctx, TokenContextKey, tokenString)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// UserRepository interface for fetching user data (reuse existing interface)
type UserRepository interface {
	GetByID(ctx context.Context, id string) (*models.User, error)
}
