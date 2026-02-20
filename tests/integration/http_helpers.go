package integration

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"sync"
	"time"

	"github.com/go-chi/chi/v5"
	chiMiddleware "github.com/go-chi/chi/v5/middleware"

	"github.com/BradenHooton/kamino/internal/auth"
	"github.com/BradenHooton/kamino/internal/config"
	"github.com/BradenHooton/kamino/internal/database"
	"github.com/BradenHooton/kamino/internal/handlers"
	middlewareCustom "github.com/BradenHooton/kamino/internal/middleware"
	"github.com/BradenHooton/kamino/internal/routes"
	"github.com/BradenHooton/kamino/internal/services"
	pkghttp "github.com/BradenHooton/kamino/pkg/http"
	pkglogger "github.com/BradenHooton/kamino/pkg/logger"
)

// SentEmail represents a captured email message
type SentEmail struct {
	To      string
	Subject string
	Body    string
}

// MockEmailService captures sent emails for test assertions
type MockEmailService struct {
	SentEmails []SentEmail
	mu         sync.Mutex
}

// SendVerificationEmail records the email
func (m *MockEmailService) SendVerificationEmail(ctx context.Context, email, token string, expiresAt time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	emailMsg := SentEmail{
		To:      email,
		Subject: "Verify your Kamino email",
		Body:    "Verification token: " + token,
	}
	m.SentEmails = append(m.SentEmails, emailMsg)
	return nil
}

// GetLastEmail returns the most recent email sent
func (m *MockEmailService) GetLastEmail() *SentEmail {
	m.mu.Lock()
	defer m.mu.Unlock()

	if len(m.SentEmails) == 0 {
		return nil
	}
	return &m.SentEmails[len(m.SentEmails)-1]
}

// TestServer wraps httptest.Server with database and all dependencies
type TestServer struct {
	Server       *httptest.Server
	Pool         *database.DB
	EmailService *MockEmailService
	Config       *config.Config

	// Dependency references for inspection in tests
	CSRFManager *auth.CSRFTokenManager
	logger      *slog.Logger
}

// NewTestServer initializes a complete HTTP server with real database + mocked email
func NewTestServer(db *database.DB) *TestServer {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelWarn}))

	// Create test config
	cfg := &config.Config{
		Auth: config.AuthConfig{
			JWTSecret:                    "test-secret-32-characters-long-for-testing",
			AccessTokenExpiry:            15 * time.Minute,
			RefreshTokenExpiry:           7 * 24 * time.Hour,
			MFATokenExpiry:               5 * time.Minute,
			TokenManagerTimeout:          2 * time.Second,
			MaxFailedAttemptsPerEmail:    5,
			EmailLockoutDuration:         15 * time.Minute,
			MaxAttemptsPerIP:             10,
			MaxAttemptsPerDevice:         5,
			RateLimitLookbackWindow:      1 * time.Hour,
			TimingDelayBaseMs:            100,
			TimingDelayRandomMs:          50,
			TimingDelayOnSuccess:         false,
			CleanupInterval:              1 * time.Hour,
		},
		MFA: config.MFAConfig{
			EncryptionKey:   []byte("test-mfa-encryption-key-32-chars!!"),
			Issuer:          "KaminoTest",
			MaxAttempts:     5,
			AttemptWindow:   15 * time.Minute,
			BackupCodeCount: 8,
		},
		Email: config.EmailConfig{
			Required:            false,
			FromAddress:         "noreply@test.local",
			VerificationURLBase: "http://localhost:3000",
			TokenExpiryHours:    24,
			AWSRegion:           "",
		},
		Server: config.ServerConfig{
			Port:             "0",
			Env:              "test",
			AllowedOrigins:   []string{},
			TrustedProxies:   []string{},
		},
	}

	// Initialize repositories
	userRepo, revokeRepo, loginAttemptRepo, emailVerifRepo, mfaDeviceRepo, mfaAttemptRepo :=
		InitializeRepositories(db)

	// Create mock email service
	mockEmail := &MockEmailService{
		SentEmails: []SentEmail{},
	}

	// Initialize TokenManager
	tokenManager := auth.NewTokenManager(
		cfg.Auth.JWTSecret,
		cfg.Auth.AccessTokenExpiry,
		cfg.Auth.RefreshTokenExpiry,
		cfg.Auth.MFATokenExpiry,
		cfg.Auth.TokenManagerTimeout,
	)

	// Set user repo for composite signing
	tokenManager.SetUserRepo(userRepo)

	// Initialize audit logger
	auditLogger := pkglogger.NewAuditLogger(logger)

	// Rate limiting service
	rateLimitConfig := services.RateLimitConfig{
		MaxFailedAttemptsPerEmail:    cfg.Auth.MaxFailedAttemptsPerEmail,
		EmailLockoutDuration:         cfg.Auth.EmailLockoutDuration,
		MaxAttemptsPerIP:             cfg.Auth.MaxAttemptsPerIP,
		MaxAttemptsPerDevice:         cfg.Auth.MaxAttemptsPerDevice,
		LookbackWindow:               cfg.Auth.RateLimitLookbackWindow,
		ProgressiveLockoutMultiplier: 1.5,
		MaxLockoutDuration:           1 * time.Hour,
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

	// Email verification service
	emailVerificationService := services.NewEmailVerificationService(
		emailVerifRepo,
		userRepo,
		mockEmail,
		logger,
		time.Duration(cfg.Email.TokenExpiryHours)*time.Hour,
	)

	// TOTP Manager
	totpManager, err := auth.NewTOTPManager(cfg.MFA.EncryptionKey, cfg.MFA.Issuer)
	if err != nil {
		logger.Error("failed to create TOTP manager", slog.Any("error", err))
		totpManager = nil
	}

	// MFA Service
	var mfaService *services.MFAService
	if totpManager != nil {
		mfaConfig := services.MFAConfig{
			MaxAttempts:     cfg.MFA.MaxAttempts,
			AttemptWindow:   cfg.MFA.AttemptWindow,
			BackupCodeCount: cfg.MFA.BackupCodeCount,
		}
		mfaService = services.NewMFAService(
			mfaDeviceRepo,
			mfaAttemptRepo,
			userRepo,
			totpManager,
			logger,
			mfaConfig,
		)
	}

	// Initialize services
	userService := services.NewUserService(userRepo, logger)
	authService := services.NewAuthService(
		userRepo,
		tokenManager,
		revokeRepo,
		rateLimitService,
		timingDelay,
		logger,
		auditLogger,
		cfg.Server.Env,
		emailVerificationService,
	)

	// Initialize handlers
	ipConfig := &pkghttp.IPConfig{
		TrustedProxies: cfg.Server.TrustedProxies,
	}
	userHandler := handlers.NewUserHandler(userService)
	authHandler := handlers.NewAuthHandlerWithEmailVerification(authService, emailVerificationService, ipConfig)

	var mfaHandler *handlers.MFAHandler
	if mfaService != nil {
		mfaHandler = handlers.NewMFAHandler(mfaService, tokenManager, userRepo, revokeRepo, logger)
	}

	// Setup Chi router with middleware
	r := chi.NewRouter()
	r.Use(chiMiddleware.RequestID)
	r.Use(chiMiddleware.RealIP)
	r.Use(middlewareCustom.SecurityHeaders(middlewareCustom.SecurityHeadersConfig{Env: cfg.Server.Env}))
	r.Use(chiMiddleware.Recoverer)
	r.Use(chiMiddleware.Timeout(60 * time.Second))

	// Setup routes using production pattern
	routes.RegisterRoutes(r, userHandler, authHandler, mfaHandler, tokenManager, userRepo, revokeRepo, csrfManager, logger)

	// Create httptest.Server
	server := httptest.NewServer(r)

	return &TestServer{
		Server:       server,
		Pool:         db,
		EmailService: mockEmail,
		Config:       cfg,
		CSRFManager:  csrfManager,
		logger:       logger,
	}
}

// Close shuts down the test server
func (ts *TestServer) Close() {
	if ts.Server != nil {
		ts.Server.Close()
	}
	if ts.CSRFManager != nil {
		ts.CSRFManager.Stop()
	}
}

// Request makes an HTTP request to the test server
func (ts *TestServer) Request(method, path string, body interface{}, headers map[string]string) (*http.Response, error) {
	url := ts.Server.URL + path

	var bodyReader io.Reader
	if body != nil {
		bodyBytes, err := json.Marshal(body)
		if err != nil {
			return nil, err
		}
		bodyReader = bytes.NewReader(bodyBytes)
	}

	req, err := http.NewRequest(method, url, bodyReader)
	if err != nil {
		return nil, err
	}

	// Set headers
	req.Header.Set("Content-Type", "application/json")
	if headers != nil {
		for key, value := range headers {
			req.Header.Set(key, value)
		}
	}

	// Get CSRF token and set it
	csrfToken, err := ts.CSRFManager.GenerateToken("")
	if err == nil && csrfToken != "" {
		req.Header.Set("X-CSRF-Token", csrfToken)
	}

	return http.DefaultClient.Do(req)
}

// RequestWithAuth makes an authenticated HTTP request with access token
func (ts *TestServer) RequestWithAuth(method, path, accessToken string, body interface{}) (*http.Response, error) {
	headers := map[string]string{
		"Authorization": "Bearer " + accessToken,
	}
	return ts.Request(method, path, body, headers)
}

// ParseJSONResponse parses JSON response body into target struct
func ParseJSONResponse(resp *http.Response, target interface{}) error {
	defer resp.Body.Close()
	return json.NewDecoder(resp.Body).Decode(target)
}

// ExtractTokensFromResponse extracts access/refresh tokens from auth response
func ExtractTokensFromResponse(resp *http.Response) (accessToken, refreshToken, mfaToken string, mfaRequired bool, err error) {
	defer resp.Body.Close()

	var authResp map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&authResp); err != nil {
		return "", "", "", false, fmt.Errorf("failed to parse response: %w", err)
	}

	if access, ok := authResp["access_token"].(string); ok {
		accessToken = access
	}
	if refresh, ok := authResp["refresh_token"].(string); ok {
		refreshToken = refresh
	}
	if mfa, ok := authResp["mfa_token"].(string); ok {
		mfaToken = mfa
	}
	if required, ok := authResp["mfa_required"].(bool); ok {
		mfaRequired = required
	}

	return
}

// GetErrorMessage extracts error message from error response
func GetErrorMessage(resp *http.Response) (string, error) {
	defer resp.Body.Close()
	var errResp map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&errResp); err != nil {
		return "", err
	}
	if msg, ok := errResp["message"].(string); ok {
		return msg, nil
	}
	return "", nil
}
