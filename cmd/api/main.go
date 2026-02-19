package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/BradenHooton/kamino/internal/auth"
	"github.com/BradenHooton/kamino/internal/background"
	"github.com/BradenHooton/kamino/internal/config"
	"github.com/BradenHooton/kamino/internal/database"
	"github.com/BradenHooton/kamino/internal/handlers"
	middlewareCustom "github.com/BradenHooton/kamino/internal/middleware"
	"github.com/BradenHooton/kamino/internal/models"
	"github.com/BradenHooton/kamino/internal/repositories"
	"github.com/BradenHooton/kamino/internal/routes"
	"github.com/BradenHooton/kamino/internal/services"
	pkgauth "github.com/BradenHooton/kamino/pkg/auth"
	pkglogger "github.com/BradenHooton/kamino/pkg/logger"
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
)

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	slog.SetDefault(logger)

	// Load configuration
	cfg, err := config.Load()
	if err != nil {
		logger.Error("failed to load configuration", slog.Any("error", err))
		os.Exit(1)
	}

	logger.Info("configuration loaded", slog.String("env", cfg.Server.Env))

	// Initialize database
	db, err := database.NewConnection(&cfg.Database, logger)
	if err != nil {
		logger.Error("failed to connect to database", slog.Any("error", err))
		os.Exit(1)
	}
	defer db.Close()

	// Initialize repositories
	userRepo := repositories.NewUserRepository(db)
	revokeRepo := repositories.NewTokenRevocationRepository(db)
	loginAttemptRepo := repositories.NewLoginAttemptRepository(db)
	emailVerificationRepo := repositories.NewEmailVerificationRepository(db)

	// Initialize cleanup manager
	cleanupManager := background.NewCleanupManager(revokeRepo, loginAttemptRepo, emailVerificationRepo, logger, cfg.Auth.CleanupInterval)

	// Initialize token manager
	tokenManager := auth.NewTokenManager(
		cfg.Auth.JWTSecret,
		cfg.Auth.AccessTokenExpiry,
		cfg.Auth.RefreshTokenExpiry,
	)

	// Enable composite signing with per-user TokenKey
	tokenManager.SetUserRepo(userRepo)

	// Initialize security services
	auditLogger := pkglogger.NewAuditLogger(logger)

	// Rate limiting service
	rateLimitConfig := services.RateLimitConfig{
		MaxFailedAttemptsPerEmail:   cfg.Auth.MaxFailedAttemptsPerEmail,
		EmailLockoutDuration:        cfg.Auth.EmailLockoutDuration,
		MaxAttemptsPerIP:            cfg.Auth.MaxAttemptsPerIP,
		MaxAttemptsPerDevice:        cfg.Auth.MaxAttemptsPerDevice,
		LookbackWindow:              cfg.Auth.RateLimitLookbackWindow,
		ProgressiveLockoutMultiplier: 1.5,
		MaxLockoutDuration:          1 * time.Hour,
	}
	rateLimitService := services.NewRateLimitService(loginAttemptRepo, rateLimitConfig, logger)

	// Timing delay for auth security
	timingConfig := auth.TimingConfig{
		BaseDelayMs:    cfg.Auth.TimingDelayBaseMs,
		RandomDelayMs:  cfg.Auth.TimingDelayRandomMs,
		DelayOnSuccess: cfg.Auth.TimingDelayOnSuccess,
	}
	timingDelay := auth.NewTimingDelay(timingConfig)

	// CSRF token manager
	csrfManager := auth.NewCSRFTokenManager()

	// AWS SES email service
	emailService, err := services.NewAWSSESEmailService(
		cfg.Email.AWSRegion,
		cfg.Email.FromAddress,
		cfg.Email.VerificationURLBase,
		logger,
	)
	if err != nil {
		logger.Error("failed to initialize email service", slog.Any("error", err))
		os.Exit(1)
	}

	// Email verification service
	emailVerificationService := services.NewEmailVerificationService(
		emailVerificationRepo,
		userRepo,
		emailService,
		logger,
		time.Duration(cfg.Email.TokenExpiryHours)*time.Hour,
	)

	// Initialize services
	userService := services.NewUserService(userRepo, logger)
	authService := services.NewAuthService(userRepo, tokenManager, revokeRepo, rateLimitService, timingDelay, logger, auditLogger, cfg.Server.Env, emailVerificationService)

	// Initialize handlers
	userHandler := handlers.NewUserHandler(userService)
	authHandler := handlers.NewAuthHandlerWithEmailVerification(authService, emailVerificationService)

	// Bootstrap first admin user if configured
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	if err := ensureAdminUser(ctx, userRepo, logger); err != nil {
		logger.Error("failed to ensure admin user", slog.Any("error", err))
	}
	cancel()

	// Setup CORS middleware
	corsConfig := middlewareCustom.DefaultCORSConfig(cfg.Server.Env)
	corsConfig.AllowedOrigins = cfg.Server.AllowedOrigins

	// Setup router
	router := chi.NewRouter()
	router.Use(middleware.RequestID)
	router.Use(middleware.RealIP)
	router.Use(middlewareCustom.SecurityHeaders(middlewareCustom.SecurityHeadersConfig{Env: cfg.Server.Env}))
	router.Use(middlewareCustom.CORS(corsConfig))
	router.Use(middlewareCustom.SecureLogger(logger))
	router.Use(middleware.Recoverer)
	router.Use(middleware.Timeout(60 * time.Second))

	// Register routes
	routes.RegisterRoutes(router, userHandler, authHandler, tokenManager, userRepo, revokeRepo, csrfManager, logger)

	// Health check with database
	router.Get("/health", func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
		defer cancel()

		if err := db.HealthCheck(ctx); err != nil {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusServiceUnavailable)
			w.Write([]byte(`{"status":"unhealthy","database":"down"}`))
			return
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status":"healthy","database":"up"}`))
	})

	// Create server
	server := &http.Server{
		Addr:         ":" + cfg.Server.Port,
		Handler:      router,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	// Start cleanup task
	cleanupCtx, cleanupCancel := context.WithCancel(context.Background())
	defer cleanupCancel()

	go cleanupManager.Start(cleanupCtx)

	// Start server
	go func() {
		logger.Info("starting server", slog.String("addr", server.Addr))
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.Error("server error", slog.Any("error", err))
			os.Exit(1)
		}
	}()

	// Graceful shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	<-sigChan

	logger.Info("shutdown signal received")

	cleanupCancel()
	cleanupManager.Stop()

	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer shutdownCancel()

	if err := server.Shutdown(shutdownCtx); err != nil {
		logger.Error("server shutdown error", slog.Any("error", err))
		os.Exit(1)
	}

	logger.Info("server stopped gracefully")
}

// ensureAdminUser creates the first admin user if ADMIN_EMAIL and ADMIN_PASSWORD are set
func ensureAdminUser(ctx context.Context, userRepo *repositories.UserRepository, logger *slog.Logger) error {
	adminEmail := os.Getenv("ADMIN_EMAIL")
	adminPassword := os.Getenv("ADMIN_PASSWORD")

	if adminEmail == "" || adminPassword == "" {
		logger.Info("no ADMIN_EMAIL or ADMIN_PASSWORD set, skipping admin user creation")
		return nil
	}

	// Check if admin already exists
	_, err := userRepo.GetByEmail(ctx, adminEmail)
	if err == nil {
		logger.Info("admin user already exists")
		return nil
	}
	if !errors.Is(err, models.ErrNotFound) {
		return fmt.Errorf("failed to check if admin exists: %w", err)
	}

	// Hash password
	hashedPassword, err := pkgauth.HashPassword(adminPassword)
	if err != nil {
		return fmt.Errorf("failed to hash admin password: %w", err)
	}

	// Create admin user
	now := time.Now()
	admin := &models.User{
		Email:             adminEmail,
		PasswordHash:      hashedPassword,
		Name:              "Admin",
		Role:              "admin",
		EmailVerified:     true,
		PasswordChangedAt: &now,
	}

	_, err = userRepo.Create(ctx, admin)
	if err != nil {
		return fmt.Errorf("failed to create admin user: %w", err)
	}

	logger.Info("admin user created successfully")
	return nil
}
