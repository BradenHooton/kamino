package routes

import (
	"log/slog"

	"github.com/BradenHooton/kamino/internal/auth"
	"github.com/BradenHooton/kamino/internal/handlers"
	"github.com/BradenHooton/kamino/internal/middleware"
	"github.com/BradenHooton/kamino/internal/models"
	"github.com/BradenHooton/kamino/internal/repositories"
	"github.com/BradenHooton/kamino/internal/services"
	"github.com/go-chi/chi/v5"
)

// RegisterRoutes registers all application routes
func RegisterRoutes(
	router chi.Router,
	userHandler *handlers.UserHandler,
	authHandler *handlers.AuthHandler,
	mfaHandler *handlers.MFAHandler,
	apiKeyHandler *handlers.APIKeyHandler,
	tokenManager *auth.TokenManager,
	userRepo *repositories.UserRepository,
	revokeRepo *repositories.TokenRevocationRepository,
	csrfManager *auth.CSRFTokenManager,
	auditHandler *handlers.AuditHandler,
	logger *slog.Logger,
	auditService *services.AuditService,
	apiKeyValidator auth.APIKeyValidator,
) {
	// Rate limiting config for auth endpoints
	rateLimitConfig := middleware.DefaultAuthRateLimit()

	// Public routes - no authentication required
	router.With(middleware.RateLimitByIP(rateLimitConfig)).Post("/auth/login", authHandler.Login)
	router.With(middleware.RateLimitByIP(rateLimitConfig)).Post("/auth/register", authHandler.Register)
	router.With(middleware.RateLimitByIP(rateLimitConfig)).Post("/auth/refresh", authHandler.RefreshToken)
	router.With(middleware.RateLimitByIP(rateLimitConfig)).Post("/auth/verify-email", authHandler.VerifyEmail)
	router.With(middleware.RateLimitByIP(rateLimitConfig)).Post("/auth/resend-verification", authHandler.ResendVerification)

	// MFA routes (only register if MFA is enabled)
	if mfaHandler != nil {
		// Protected MFA management routes
		router.Group(func(r chi.Router) {
			revocationConfig := auth.RevocationConfig{FailClosed: true}
			r.Use(auth.AuthMiddlewareWithRevocation(tokenManager, revokeRepo, revocationConfig))
			r.Use(middleware.CSRFProtection(csrfManager, logger))

			r.Post("/mfa/setup", mfaHandler.InitiateSetup)
			r.Post("/mfa/setup/verify", mfaHandler.VerifySetup)
			r.Post("/mfa/disable", mfaHandler.DisableMFA)
			r.Get("/mfa/status", mfaHandler.GetStatus)
		})

		// Public MFA verification route (rate-limited)
		router.With(middleware.RateLimitByIP(rateLimitConfig)).Post("/auth/mfa/verify", mfaHandler.VerifyMFACode)
	}

	// Protected routes - authentication required (supports both JWT and API keys)
	router.Group(func(r chi.Router) {
		revocationConfig := auth.RevocationConfig{FailClosed: true}
		r.Use(auth.AuthMiddlewareWithAPIKey(tokenManager, apiKeyValidator, revokeRepo, revocationConfig, auditService))
		r.Use(middleware.CSRFProtection(csrfManager, logger))

		// User endpoints with scope enforcement
		r.With(auth.RequireScope(models.ScopeUsersRead)).Get("/users/{id}", userHandler.GetUser)
		r.With(auth.RequireScope(models.ScopeUsersWrite)).Put("/users/{id}", userHandler.UpdateUser)

		// Auth endpoints (no scope required - all authenticated users)
		r.Post("/auth/logout", authHandler.Logout)
		r.Post("/auth/logout-all", authHandler.LogoutAll)
		r.Get("/auth/verification-status", authHandler.VerificationStatus)

		// API Key endpoints with scope enforcement (only register if apiKeyHandler is provided)
		if apiKeyHandler != nil {
			r.With(auth.RequireScope(models.ScopeAPIKeysCreate)).Post("/api-keys", apiKeyHandler.CreateAPIKey)
			r.With(auth.RequireScope(models.ScopeAPIKeysRead)).Get("/api-keys", apiKeyHandler.ListAPIKeys)
			r.With(auth.RequireScope(models.ScopeAPIKeysRead)).Get("/api-keys/{id}", apiKeyHandler.GetAPIKey)
			r.With(auth.RequireScope(models.ScopeAPIKeysRevoke)).Delete("/api-keys/{id}", apiKeyHandler.RevokeAPIKey)
		}

		// Admin-only routes
		r.Group(func(r chi.Router) {
			r.Use(auth.RequireRole(userRepo, "admin"))
			r.Get("/users", userHandler.ListUsers)
			r.Post("/users", userHandler.CreateUser)
			r.With(auth.RequireScope(models.ScopeUsersDelete)).Delete("/users/{id}", userHandler.DeleteUser)

			// Audit routes
			if auditHandler != nil {
				r.With(auth.RequireScope(models.ScopeAuditRead)).Get("/users/{id}/audit", auditHandler.GetUserAuditTrail)
				r.With(auth.RequireScope(models.ScopeAuditRead)).Get("/api-keys/{id}/usage", auditHandler.GetAPIKeyUsage)
			}
		})
	})
}
