package routes

import (
	"log/slog"

	"github.com/BradenHooton/kamino/internal/auth"
	"github.com/BradenHooton/kamino/internal/handlers"
	"github.com/BradenHooton/kamino/internal/middleware"
	"github.com/BradenHooton/kamino/internal/repositories"
	"github.com/go-chi/chi/v5"
)

// RegisterRoutes registers all application routes
func RegisterRoutes(
	router chi.Router,
	userHandler *handlers.UserHandler,
	authHandler *handlers.AuthHandler,
	mfaHandler *handlers.MFAHandler,
	tokenManager *auth.TokenManager,
	userRepo *repositories.UserRepository,
	revokeRepo *repositories.TokenRevocationRepository,
	csrfManager *auth.CSRFTokenManager,
	logger *slog.Logger,
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

	// Protected routes - authentication required
	router.Group(func(r chi.Router) {
		revocationConfig := auth.RevocationConfig{FailClosed: true}
		r.Use(auth.AuthMiddlewareWithRevocation(tokenManager, revokeRepo, revocationConfig))
		r.Use(middleware.CSRFProtection(csrfManager, logger))

		// Any authenticated user
		r.Get("/users/{id}", userHandler.GetUser)
		r.Put("/users/{id}", userHandler.UpdateUser)

		// Auth endpoints
		r.Post("/auth/logout", authHandler.Logout)
		r.Post("/auth/logout-all", authHandler.LogoutAll)
		r.Get("/auth/verification-status", authHandler.VerificationStatus)

		// Admin-only routes
		r.Group(func(r chi.Router) {
			r.Use(auth.RequireRole(userRepo, "admin"))
			r.Get("/users", userHandler.ListUsers)
			r.Post("/users", userHandler.CreateUser)
			r.Delete("/users/{id}", userHandler.DeleteUser)
		})
	})
}
