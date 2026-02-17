package routes

import (
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
	tokenManager *auth.TokenManager,
	userRepo *repositories.UserRepository,
	revokeRepo *repositories.TokenRevocationRepository,
) {
	// Rate limiting config for auth endpoints
	rateLimitConfig := middleware.DefaultAuthRateLimit()

	// Public routes - no authentication required
	router.With(middleware.RateLimitByIP(rateLimitConfig)).Post("/auth/login", authHandler.Login)
	router.With(middleware.RateLimitByIP(rateLimitConfig)).Post("/auth/refresh", authHandler.RefreshToken)

	// Protected routes - authentication required
	router.Group(func(r chi.Router) {
		r.Use(auth.AuthMiddlewareWithRevocation(tokenManager, revokeRepo))

		// Any authenticated user
		r.Get("/users/{id}", userHandler.GetUser)
		r.Put("/users/{id}", userHandler.UpdateUser)

		// Auth endpoints
		r.Post("/auth/logout", authHandler.Logout)
		r.Post("/auth/logout-all", authHandler.LogoutAll)

		// Admin-only routes
		r.Group(func(r chi.Router) {
			r.Use(auth.RequireRole(userRepo, "admin"))
			r.Post("/auth/register", authHandler.Register)
			r.Get("/users", userHandler.ListUsers)
			r.Post("/users", userHandler.CreateUser)
			r.Delete("/users/{id}", userHandler.DeleteUser)
		})
	})
}
