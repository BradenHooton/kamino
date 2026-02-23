package routes

import (
	"log/slog"

	"github.com/BradenHooton/kamino/internal/auth"
	"github.com/BradenHooton/kamino/internal/config"
	"github.com/BradenHooton/kamino/internal/handlers"
	"github.com/BradenHooton/kamino/internal/middleware"
	"github.com/BradenHooton/kamino/internal/models"
	"github.com/BradenHooton/kamino/internal/repositories"
	"github.com/BradenHooton/kamino/internal/services"
	pkghttp "github.com/BradenHooton/kamino/pkg/http"
	"github.com/go-chi/chi/v5"
)

// RegisterRoutes registers all application routes
func RegisterRoutes(
	router chi.Router,
	userHandler *handlers.UserHandler,
	authHandler *handlers.AuthHandler,
	mfaHandler *handlers.MFAHandler,
	apiKeyHandler *handlers.APIKeyHandler,
	recoveryHandler *handlers.MFARecoveryHandler,
	tokenManager *auth.TokenManager,
	userRepo *repositories.UserRepository,
	revokeRepo *repositories.TokenRevocationRepository,
	csrfManager *auth.CSRFTokenManager,
	auditHandler *handlers.AuditHandler,
	logger *slog.Logger,
	auditService *services.AuditService,
	apiKeyValidator auth.APIKeyValidator,
	cfg *config.Config,
	ipConfig *pkghttp.IPConfig,
	adminHandler *handlers.AdminHandler,
) {
	// Rate limiting config for auth endpoints
	rateLimitConfig := middleware.DefaultAuthRateLimit()

	// Authenticated rate limiting config (per-user)
	authRateLimitConfig := middleware.AuthenticatedRateLimitConfig{
		ReadOperationsPerMinute:  cfg.Auth.AuthenticatedReadOpsPerMin,
		WriteOperationsPerMinute: cfg.Auth.AuthenticatedWriteOpsPerMin,
		AdminOperationsPerMinute: cfg.Auth.AuthenticatedAdminOpsPerMin,
	}

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
		r.Use(auth.AuthMiddlewareWithAPIKey(tokenManager, apiKeyValidator, revokeRepo, revocationConfig, auditService, ipConfig))
		r.Use(middleware.CSRFProtection(csrfManager, logger))

		// User endpoints with scope enforcement
		r.With(
			auth.RequireScope(models.ScopeUsersRead),
			middleware.RateLimitByUserID(authRateLimitConfig, "read"),
		).Get("/users/{id}", userHandler.GetUser)
		r.With(
			auth.RequireScope(models.ScopeUsersWrite),
			middleware.RateLimitByUserID(authRateLimitConfig, "write"),
		).Put("/users/{id}", userHandler.UpdateUser)

		// Auth endpoints (no scope required - all authenticated users)
		r.With(middleware.RateLimitByUserID(authRateLimitConfig, "write")).Post("/auth/logout", authHandler.Logout)
		r.With(middleware.RateLimitByUserID(authRateLimitConfig, "write")).Post("/auth/logout-all", authHandler.LogoutAll)
		r.With(middleware.RateLimitByUserID(authRateLimitConfig, "read")).Get("/auth/verification-status", authHandler.VerificationStatus)

		// API Key endpoints with scope enforcement (only register if apiKeyHandler is provided)
		if apiKeyHandler != nil {
			r.With(
				auth.RequireScope(models.ScopeAPIKeysCreate),
				middleware.RateLimitByUserID(authRateLimitConfig, "write"),
			).Post("/api-keys", apiKeyHandler.CreateAPIKey)
			r.With(
				auth.RequireScope(models.ScopeAPIKeysRead),
				middleware.RateLimitByUserID(authRateLimitConfig, "read"),
			).Get("/api-keys", apiKeyHandler.ListAPIKeys)
			r.With(
				auth.RequireScope(models.ScopeAPIKeysRead),
				middleware.RateLimitByUserID(authRateLimitConfig, "read"),
			).Get("/api-keys/{id}", apiKeyHandler.GetAPIKey)
			r.With(
				auth.RequireScope(models.ScopeAPIKeysRevoke),
				middleware.RateLimitByUserID(authRateLimitConfig, "write"),
			).Delete("/api-keys/{id}", apiKeyHandler.RevokeAPIKey)
		}

		// Admin-only routes
		r.Group(func(r chi.Router) {
			r.Use(auth.RequireRole(userRepo, "admin"))
			r.With(middleware.RateLimitByUserID(authRateLimitConfig, "admin")).Get("/users", userHandler.ListUsers)
			r.With(middleware.RateLimitByUserID(authRateLimitConfig, "write")).Post("/users", userHandler.CreateUser)
			r.With(
				auth.RequireScope(models.ScopeUsersDelete),
				middleware.RateLimitByUserID(authRateLimitConfig, "write"),
			).Delete("/users/{id}", userHandler.DeleteUser)

			r.With(
				auth.RequireScope(models.ScopeUsersSuspend),
				middleware.RateLimitByUserID(authRateLimitConfig, "admin"),
			).Patch("/users/{id}/status", userHandler.UpdateUserStatus)

			r.With(
				auth.RequireScope(models.ScopeUsersLock),
				middleware.RateLimitByUserID(authRateLimitConfig, "admin"),
			).Patch("/users/{id}/lock", userHandler.LockUser)

			r.With(
				auth.RequireScope(models.ScopeUsersRead),
				middleware.RateLimitByUserID(authRateLimitConfig, "admin"),
			).Post("/users/search", userHandler.SearchUsers)

			// Audit routes
			if auditHandler != nil {
				r.With(
					auth.RequireScope(models.ScopeAuditRead),
					middleware.RateLimitByUserID(authRateLimitConfig, "admin"),
				).Get("/users/{id}/audit", auditHandler.GetUserAuditTrail)
				r.With(
					auth.RequireScope(models.ScopeAuditRead),
					middleware.RateLimitByUserID(authRateLimitConfig, "admin"),
				).Get("/api-keys/{id}/usage", auditHandler.GetAPIKeyUsage)
			}

			// MFA Recovery routes
			if recoveryHandler != nil {
				r.With(auth.RequireScope(models.ScopeMFAAdmin)).Post("/admin/mfa/recovery", recoveryHandler.InitiateRecovery)
				r.With(auth.RequireScope(models.ScopeMFAAdmin)).Post("/admin/mfa/recovery/{id}/confirm", recoveryHandler.ConfirmRecovery)
				r.With(auth.RequireScope(models.ScopeMFAAdmin)).Post("/admin/mfa/recovery/{id}/execute", recoveryHandler.ExecuteRecovery)
				r.With(auth.RequireScope(models.ScopeMFAAdmin)).Get("/admin/mfa/recovery", recoveryHandler.ListPendingRecoveries)
				r.With(auth.RequireScope(models.ScopeMFAAdmin)).Delete("/admin/mfa/recovery/{id}", recoveryHandler.CancelRecovery)
			}

			// Dashboard routes (admin only)
			if adminHandler != nil {
				r.With(
					auth.RequireScope(models.ScopeAdminDashboard),
					middleware.RateLimitByUserID(authRateLimitConfig, "admin"),
				).Get("/admin/dashboard/stats", adminHandler.GetDashboardStats)
				r.With(
					auth.RequireScope(models.ScopeAdminDashboard),
					middleware.RateLimitByUserID(authRateLimitConfig, "admin"),
				).Get("/admin/dashboard/activity", adminHandler.GetRecentActivity)
			}
		})
	})
}
