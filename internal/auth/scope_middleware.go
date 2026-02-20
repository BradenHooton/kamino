package auth

import (
	"context"
	"net/http"

	"github.com/BradenHooton/kamino/internal/models"
	pkghttp "github.com/BradenHooton/kamino/pkg/http"
)

// RequireScope creates middleware that enforces scope requirement for API keys
// JWT tokens bypass scope checks (they represent authenticated users with role-based access)
// API keys must have the required scope or be denied access
// Stores required scope in context for audit logging
func RequireScope(requiredScope string) func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			claims := GetUserFromContext(r)
			if claims == nil {
				pkghttp.WriteUnauthorized(w, "unauthorized")
				return
			}

			// JWT tokens (Type != "api_key") bypass scope checks
			// They already passed role-based authorization
			if claims.Type != "api_key" {
				next.ServeHTTP(w, r)
				return
			}

			// API keys must have the required scope
			if !models.HasScope(claims.Scopes, requiredScope) {
				pkghttp.WriteForbidden(w, "insufficient scope")
				return
			}

			// Store required scope in context for audit logging
			ctx := r.Context()
			ctx = context.WithValue(ctx, RequiredScopesContextKey, []string{requiredScope})
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// RequireAnyScope creates middleware that allows access if ANY of the provided scopes match
// Useful for endpoints that accept multiple scopes
// Stores required scopes in context for audit logging
func RequireAnyScope(requiredScopes ...string) func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			claims := GetUserFromContext(r)
			if claims == nil {
				pkghttp.WriteUnauthorized(w, "unauthorized")
				return
			}

			// JWT tokens bypass scope checks
			if claims.Type != "api_key" {
				next.ServeHTTP(w, r)
				return
			}

			// Check if any required scope is present
			for _, scope := range requiredScopes {
				if models.HasScope(claims.Scopes, scope) {
					// Store required scopes in context for audit logging
					ctx := r.Context()
					ctx = context.WithValue(ctx, RequiredScopesContextKey, requiredScopes)
					next.ServeHTTP(w, r.WithContext(ctx))
					return
				}
			}

			// No matching scopes found
			pkghttp.WriteForbidden(w, "insufficient scope")
		})
	}
}

// RequireAllScopes creates middleware that requires ALL provided scopes to be present
// Useful for endpoints that need multiple permissions
// Stores required scopes in context for audit logging
func RequireAllScopes(requiredScopes ...string) func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			claims := GetUserFromContext(r)
			if claims == nil {
				pkghttp.WriteUnauthorized(w, "unauthorized")
				return
			}

			// JWT tokens bypass scope checks
			if claims.Type != "api_key" {
				next.ServeHTTP(w, r)
				return
			}

			// Check if all required scopes are present
			for _, requiredScope := range requiredScopes {
				if !models.HasScope(claims.Scopes, requiredScope) {
					pkghttp.WriteForbidden(w, "insufficient scope")
					return
				}
			}

			// Store required scopes in context for audit logging
			ctx := r.Context()
			ctx = context.WithValue(ctx, RequiredScopesContextKey, requiredScopes)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}
