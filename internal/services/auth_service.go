package services

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/BradenHooton/kamino/internal/auth"
	"github.com/BradenHooton/kamino/internal/models"
	pkgauth "github.com/BradenHooton/kamino/pkg/auth"
	pkglogger "github.com/BradenHooton/kamino/pkg/logger"
)

// TokenRevocationRepository defines the interface for token revocation operations
type TokenRevocationRepository interface {
	RevokeToken(ctx context.Context, jti, userID, tokenType string, expiresAt time.Time, reason string) error
	RevokeAllUserTokens(ctx context.Context, userID, reason string) error
	IsTokenRevoked(ctx context.Context, jti string) (bool, error)
}

// AuthService handles authentication business logic
type AuthService struct {
	repo                      UserRepository
	revokeRepo                TokenRevocationRepository
	tm                        *auth.TokenManager
	rateLimitService          *RateLimitService
	timingDelay               *auth.TimingDelay
	logger                    *slog.Logger
	auditLogger               *pkglogger.AuditLogger
	env                       string
	emailVerificationService  *EmailVerificationService
}

// NewAuthService creates a new AuthService
func NewAuthService(repo UserRepository, tm *auth.TokenManager, revokeRepo TokenRevocationRepository, rateLimitService *RateLimitService, timingDelay *auth.TimingDelay, logger *slog.Logger, auditLogger *pkglogger.AuditLogger, env string, emailVerificationService *EmailVerificationService) *AuthService {
	return &AuthService{
		repo:                     repo,
		revokeRepo:               revokeRepo,
		tm:                       tm,
		rateLimitService:         rateLimitService,
		timingDelay:              timingDelay,
		logger:                   logger,
		auditLogger:              auditLogger,
		env:                      env,
		emailVerificationService: emailVerificationService,
	}
}

// UserResponse represents a user in the HTTP response
type UserResponse struct {
	ID            string `json:"id"`
	Email         string `json:"email"`
	Name          string `json:"name"`
	EmailVerified bool   `json:"email_verified"`
	Role          string `json:"role"`
	CreatedAt     string `json:"created_at"`
	UpdatedAt     string `json:"updated_at"`
}

// AuthResponse represents the response from auth operations
type AuthResponse struct {
	AccessToken  string       `json:"access_token"`
	RefreshToken string       `json:"refresh_token"`
	User         *UserResponse `json:"user"`
}

// Login authenticates a user and returns tokens
// ipAddress and userAgent are used for rate limiting and device fingerprinting
func (s *AuthService) Login(ctx context.Context, email, password, ipAddress, userAgent string) (*AuthResponse, error) {
	startTime := time.Now()
	var authErr error

	// Defer timing delay to ensure it always runs on failure
	defer func() {
		if authErr != nil {
			s.timingDelay.WaitFrom(startTime, false)
		}
	}()

	if email = strings.ToLower(strings.TrimSpace(email)); email == "" {
		s.logger.Warn("login attempt with empty email")
		authErr = models.ErrUnauthorized
		return nil, authErr
	}

	// 1. Check rate limiting BEFORE password validation (fail-open for DB errors)
	allowed, lockoutDuration, err := s.rateLimitService.CheckRateLimit(ctx, email, ipAddress, userAgent)
	if err != nil && !errors.Is(err, models.ErrRateLimitExceeded) {
		s.logger.Error("rate limit check error", slog.Any("error", err))
		// Fail open for availability - rate limit DB errors shouldn't block login
		// Rate limit violations (detected successfully) still fail closed below
	}

	if !allowed {
		if lockoutDuration != nil {
			// Account has exceeded failed attempts - apply temporary lock
			lockedUntil := time.Now().Add(*lockoutDuration)

			// Try to lock the account in the database
			// Fetch the user first to get current state
			lockedUser, fetchErr := s.repo.GetByEmail(ctx, email)
			if fetchErr == nil {
				// Update user with lock
				lockedUser.LockedUntil = &lockedUntil
				_, updateErr := s.repo.Update(ctx, lockedUser.ID, lockedUser)
				if updateErr != nil {
					s.logger.Error("failed to lock account",
						slog.String("email", email),
						slog.Any("error", updateErr))
				} else {
					s.logger.Warn("account locked due to failed attempts",
						slog.String("email", email),
						slog.String("user_id", lockedUser.ID),
						slog.Duration("lockout_duration", *lockoutDuration))
					s.auditLogger.LogAuthAttempt(pkglogger.AuditEvent{
						EventType:     "account_locked",
						UserID:        lockedUser.ID,
						FailureReason: "too_many_failed_attempts",
						Success:       false,
					})
				}
			}
			authErr = models.ErrAccountLockedBySystem
		} else {
			s.logger.Warn("rate limit exceeded", slog.String("ip", ipAddress))
			authErr = models.ErrRateLimitExceeded
		}
		return nil, authErr
	}

	user, err := s.repo.GetByEmail(ctx, email)
	if err != nil {
		if errors.Is(err, models.ErrNotFound) {
			// Log login failure without exposing email
			s.logger.Info("login failed: invalid credentials")
			failureReason := "user_not_found"
			_ = s.rateLimitService.RecordLoginAttempt(ctx, email, ipAddress, userAgent, false, &failureReason)
			s.auditLogger.LogAuthAttempt(pkglogger.AuditEvent{
				EventType:     "login_failed",
				FailureReason: "invalid_credentials",
				Success:       false,
			})
			authErr = models.ErrUnauthorized
			return nil, authErr
		}
		s.logger.Error("failed to get user by email", slog.Any("error", err))
		authErr = models.ErrInternalServer
		return nil, authErr
	}

	// Check account status
	if err := validateAccountState(user); err != nil {
		s.logger.Info("login blocked due to account state",
			slog.String("user_id", user.ID),
			slog.String("status", user.Status),
			slog.Any("error", err))
		failureReason := "account_blocked"
		_ = s.rateLimitService.RecordLoginAttempt(ctx, email, ipAddress, userAgent, false, &failureReason)
		s.auditLogger.LogAuthAttempt(pkglogger.AuditEvent{
			EventType:     "login_failed",
			UserID:        user.ID,
			FailureReason: "account_blocked",
			Success:       false,
		})
		authErr = err
		return nil, authErr
	}

	// Check email verification (Option A: Restrictive - no login until verified)
	if !user.EmailVerified {
		s.logger.Info("login blocked: email not verified", slog.String("user_id", user.ID))
		failureReason := "email_not_verified"
		_ = s.rateLimitService.RecordLoginAttempt(ctx, email, ipAddress, userAgent, false, &failureReason)
		s.auditLogger.LogAuthAttempt(pkglogger.AuditEvent{
			EventType:     "login_failed",
			UserID:        user.ID,
			FailureReason: "email_not_verified",
			Success:       false,
		})
		authErr = models.ErrEmailNotVerified
		return nil, authErr
	}

	// Verify password
	if err := pkgauth.ComparePassword(user.PasswordHash, password); err != nil {
		s.logger.Info("login failed: invalid credentials")
		failureReason := "invalid_password"
		_ = s.rateLimitService.RecordLoginAttempt(ctx, email, ipAddress, userAgent, false, &failureReason)
		s.auditLogger.LogAuthAttempt(pkglogger.AuditEvent{
			EventType:     "login_failed",
			UserID:        user.ID,
			FailureReason: "invalid_credentials",
			Success:       false,
		})
		authErr = models.ErrUnauthorized
		return nil, authErr
	}

	// Generate tokens
	accessToken, err := s.tm.GenerateAccessToken(user.ID, user.Email)
	if err != nil {
		s.logger.Error("failed to generate access token", slog.String("user_id", user.ID), slog.Any("error", err))
		authErr = models.ErrInternalServer
		return nil, authErr
	}

	refreshToken, err := s.tm.GenerateRefreshToken(user.ID, user.Email)
	if err != nil {
		s.logger.Error("failed to generate refresh token", slog.String("user_id", user.ID), slog.Any("error", err))
		authErr = models.ErrInternalServer
		return nil, authErr
	}

	// Record successful login attempt
	_ = s.rateLimitService.RecordLoginAttempt(ctx, email, ipAddress, userAgent, true, nil)

	// Clear any temporary locks on successful login
	if user.LockedUntil != nil {
		user.LockedUntil = nil
		_, err := s.repo.Update(ctx, user.ID, user)
		if err != nil {
			s.logger.Error("failed to clear account lock on successful login",
				slog.String("user_id", user.ID),
				slog.Any("error", err))
		} else {
			s.logger.Info("account lock cleared after successful login", slog.String("user_id", user.ID))
			s.auditLogger.LogAuthAttempt(pkglogger.AuditEvent{
				EventType: "account_lock_cleared",
				UserID:    user.ID,
				Success:   true,
			})
		}
	}

	s.logger.Info("user logged in", slog.String("user_id", user.ID))
	s.auditLogger.LogAuthAttempt(pkglogger.AuditEvent{
		EventType: "login_success",
		UserID:    user.ID,
		Success:   true,
	})

	// Set authErr to nil to prevent timing delay on success
	authErr = nil
	return &AuthResponse{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		User:         userModelToResponse(user),
	}, nil
}

// RefreshToken generates a new token pair from a refresh token
func (s *AuthService) RefreshToken(ctx context.Context, refreshTokenString string) (*AuthResponse, error) {
	if refreshTokenString = strings.TrimSpace(refreshTokenString); refreshTokenString == "" {
		return nil, models.ErrUnauthorized
	}

	// Validate the refresh token
	claims, err := s.tm.ValidateToken(refreshTokenString)
	if err != nil {
		s.logger.Info("refresh token validation failed", slog.Any("error", err))
		return nil, models.ErrUnauthorized
	}

	// Verify it's a refresh token
	if claims.Type != "refresh" {
		s.logger.Warn("refresh attempt with non-refresh token", slog.String("user_id", claims.UserID))
		return nil, models.ErrUnauthorized
	}

	// Fetch fresh user data
	user, err := s.repo.GetByID(ctx, claims.UserID)
	if err != nil {
		if errors.Is(err, models.ErrNotFound) {
			s.logger.Info("user not found for token refresh", slog.String("user_id", claims.UserID))
			return nil, models.ErrUnauthorized
		}
		s.logger.Error("failed to get user for token refresh", slog.String("user_id", claims.UserID), slog.Any("error", err))
		return nil, models.ErrInternalServer
	}

	// Validate account state
	if err := validateAccountState(user); err != nil {
		s.logger.Info("token refresh blocked due to account state",
			slog.String("user_id", user.ID),
			slog.String("status", user.Status))
		return nil, models.ErrUnauthorized
	}

	// Invalidate tokens if password changed after token was issued
	if user.PasswordChangedAt != nil && claims.IssuedAt != nil {
		tokenIssuedAt := claims.IssuedAt.Time
		if tokenIssuedAt.Before(*user.PasswordChangedAt) {
			s.logger.Info("token refresh blocked: issued before password change",
				slog.String("user_id", user.ID))
			return nil, models.ErrUnauthorized
		}
	}

	// Extract JTI from old refresh token for revocation
	oldTokenJTI := claims.ID
	if oldTokenJTI == "" {
		s.logger.Warn("refresh token missing JTI", slog.String("user_id", user.ID))
		return nil, models.ErrUnauthorized
	}

	// Extract expiration time for revocation record
	var oldTokenExpiresAt time.Time
	if claims.ExpiresAt != nil {
		oldTokenExpiresAt = claims.ExpiresAt.Time
	} else {
		// Fallback: if no expiration in claims, use reasonable default
		s.logger.Warn("refresh token missing expiration", slog.String("user_id", user.ID))
		oldTokenExpiresAt = time.Now().Add(7 * 24 * time.Hour)
	}

	// Revoke the old refresh token to prevent replay attacks
	// CRITICAL: Must succeed before we issue new tokens (fail-closed approach)
	if err := s.revokeRepo.RevokeToken(
		ctx,
		oldTokenJTI,
		user.ID,
		"refresh",
		oldTokenExpiresAt,
		"token_refresh",
	); err != nil {
		s.logger.Error("failed to revoke old refresh token",
			slog.String("user_id", user.ID),
			slog.String("jti", oldTokenJTI),
			slog.Any("error", err))

		// Do not issue new tokens if revocation fails
		return nil, models.ErrInternalServer
	}

	s.logger.Info("old refresh token revoked",
		slog.String("user_id", user.ID),
		slog.String("jti", oldTokenJTI))

	// Generate new token pair
	accessToken, err := s.tm.GenerateAccessToken(user.ID, user.Email)
	if err != nil {
		s.logger.Error("failed to generate access token", slog.String("user_id", user.ID), slog.Any("error", err))
		return nil, models.ErrInternalServer
	}

	newRefreshToken, err := s.tm.GenerateRefreshToken(user.ID, user.Email)
	if err != nil {
		s.logger.Error("failed to generate refresh token", slog.String("user_id", user.ID), slog.Any("error", err))
		return nil, models.ErrInternalServer
	}

	s.logger.Info("token refreshed successfully",
		slog.String("user_id", user.ID),
		slog.String("old_jti", oldTokenJTI))

	return &AuthResponse{
		AccessToken:  accessToken,
		RefreshToken: newRefreshToken,
		User:         userModelToResponse(user),
	}, nil
}

// Register creates a new user account
func (s *AuthService) Register(ctx context.Context, email, password, name string) (*AuthResponse, error) {
	// Normalize inputs
	email = strings.ToLower(strings.TrimSpace(email))
	name = strings.TrimSpace(name)

	// Validate inputs
	if email == "" {
		return nil, fmt.Errorf("email is required")
	}
	if name == "" {
		return nil, fmt.Errorf("name is required")
	}

	// Validate password
	if err := pkgauth.ValidatePassword(password); err != nil {
		return nil, err
	}

	// Check if user already exists
	existingUser, err := s.repo.GetByEmail(ctx, email)
	if err == nil {
		// User exists - log it but don't reveal this to caller
		s.logger.Info("registration attempt for existing email",
			slog.String("email", email),
			slog.String("existing_user_id", existingUser.ID))

		// Return conflict error (handler will convert to generic response)
		return nil, models.ErrConflict
	}
	if !errors.Is(err, models.ErrNotFound) {
		s.logger.Error("failed to check if user exists", slog.Any("error", err))
		return nil, models.ErrInternalServer
	}

	// Hash password
	hashedPassword, err := pkgauth.HashPassword(password)
	if err != nil {
		s.logger.Error("failed to hash password", slog.Any("error", err))
		return nil, models.ErrInternalServer
	}

	// Create user with email unverified
	now := time.Now()
	user := &models.User{
		Email:             email,
		PasswordHash:      hashedPassword,
		Name:              name,
		EmailVerified:     false, // Require email verification before login
		Role:              "user",
		PasswordChangedAt: &now,
	}

	createdUser, err := s.repo.Create(ctx, user)
	if err != nil {
		s.logger.Error("failed to create user", slog.Any("error", err))
		if errors.Is(err, models.ErrConflict) {
			return nil, models.ErrConflict
		}
		return nil, models.ErrInternalServer
	}

	s.logger.Info("user registered", slog.String("user_id", createdUser.ID))
	s.auditLogger.LogAccountAction("user_registered", createdUser.ID, "", nil)

	// Send verification email (don't fail registration if email send fails)
	if s.emailVerificationService != nil {
		if err := s.emailVerificationService.SendVerificationEmail(ctx, createdUser.ID, createdUser.Email); err != nil {
			s.logger.Error("failed to send verification email",
				slog.String("user_id", createdUser.ID),
				slog.Any("error", err))
			// Log but don't fail - user can request resend
		}
	}

	// Return empty AuthResponse - tokens are not generated during registration
	// because the handler returns a generic response for security (anti-enumeration)
	// Users must verify email and log in separately to get tokens
	return &AuthResponse{}, nil
}

// Logout revokes the current access token
func (s *AuthService) Logout(ctx context.Context, accessToken string) error {
	// Validate token to extract claims
	claims, err := s.tm.ValidateToken(accessToken)
	if err != nil {
		return models.ErrUnauthorized
	}

	// Revoke the access token
	expiresAt := claims.ExpiresAt.Time
	err = s.revokeRepo.RevokeToken(ctx, claims.ID, claims.UserID, claims.Type, expiresAt, "logout")
	if err != nil {
		s.logger.Error("failed to revoke token", slog.String("jti", claims.ID), slog.Any("error", err))
		return models.ErrInternalServer
	}

	s.logger.Info("user logged out", slog.String("user_id", claims.UserID))
	return nil
}

// LogoutAll revokes all tokens for the current user (e.g., "logout all devices")
func (s *AuthService) LogoutAll(ctx context.Context, userID string) error {
	// Revoke all user tokens in database
	err := s.revokeRepo.RevokeAllUserTokens(ctx, userID, "logout_all")
	if err != nil {
		s.logger.Error("failed to revoke all user tokens", slog.String("user_id", userID), slog.Any("error", err))
		return models.ErrInternalServer
	}

	// Also rotate user's TokenKey for defense-in-depth
	// (This invalidates any tokens not yet in the revocation list)
	newTokenKey, err := pkgauth.GenerateTokenKey()
	if err != nil {
		s.logger.Error("failed to generate new token key", slog.Any("error", err))
		return models.ErrInternalServer
	}

	user := &models.User{ID: userID, TokenKey: newTokenKey}
	_, err = s.repo.Update(ctx, userID, user)
	if err != nil {
		s.logger.Error("failed to update token key", slog.String("user_id", userID), slog.Any("error", err))
		return models.ErrInternalServer
	}

	s.logger.Info("user logged out from all devices", slog.String("user_id", userID))
	return nil
}

// validateAccountState checks if user account is in valid state for authentication
func validateAccountState(user *models.User) error {
	// Check account status
	switch user.Status {
	case "disabled":
		return models.ErrAccountDisabled
	case "suspended":
		return models.ErrAccountSuspended
	case "active":
		// Continue to other checks
	default:
		return fmt.Errorf("unknown account status: %s", user.Status)
	}

	// Check temporary lock
	if user.LockedUntil != nil && time.Now().Before(*user.LockedUntil) {
		return models.ErrAccountLocked
	}

	return nil
}

// userModelToResponse converts a user model to response DTO (reuse from handlers)
func userModelToResponse(user *models.User) *UserResponse {
	return &UserResponse{
		ID:            user.ID,
		Email:         user.Email,
		Name:          user.Name,
		EmailVerified: user.EmailVerified,
		Role:          user.Role,
		CreatedAt:     user.CreatedAt.Format("2006-01-02T15:04:05Z07:00"),
		UpdatedAt:     user.UpdatedAt.Format("2006-01-02T15:04:05Z07:00"),
	}
}
