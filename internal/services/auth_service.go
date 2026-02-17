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
	repo         UserRepository
	revokeRepo   TokenRevocationRepository
	tm           *auth.TokenManager
	logger       *slog.Logger
	auditLogger  *pkglogger.AuditLogger
	env          string
}

// NewAuthService creates a new AuthService
func NewAuthService(repo UserRepository, tm *auth.TokenManager, revokeRepo TokenRevocationRepository, logger *slog.Logger, auditLogger *pkglogger.AuditLogger, env string) *AuthService {
	return &AuthService{
		repo:        repo,
		revokeRepo:  revokeRepo,
		tm:          tm,
		logger:      logger,
		auditLogger: auditLogger,
		env:         env,
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
func (s *AuthService) Login(ctx context.Context, email, password string) (*AuthResponse, error) {
	if email = strings.ToLower(strings.TrimSpace(email)); email == "" {
		s.logger.Warn("login attempt with empty email")
		return nil, models.ErrUnauthorized
	}

	user, err := s.repo.GetByEmail(ctx, email)
	if err != nil {
		if errors.Is(err, models.ErrNotFound) {
			// Log login failure without exposing email
			s.logger.Info("login failed: invalid credentials")
			s.auditLogger.LogAuthAttempt(pkglogger.AuditEvent{
				EventType:     "login_failed",
				FailureReason: "invalid_credentials",
				Success:       false,
			})
			return nil, models.ErrUnauthorized
		}
		s.logger.Error("failed to get user by email", slog.Any("error", err))
		return nil, models.ErrInternalServer
	}

	// Check account status
	if err := validateAccountState(user); err != nil {
		s.logger.Info("login blocked due to account state",
			slog.String("user_id", user.ID),
			slog.String("status", user.Status),
			slog.Any("error", err))
		s.auditLogger.LogAuthAttempt(pkglogger.AuditEvent{
			EventType:     "login_failed",
			UserID:        user.ID,
			FailureReason: "account_blocked",
			Success:       false,
		})
		return nil, err
	}

	// Enforce email verification
	if !user.EmailVerified {
		s.logger.Info("login blocked: email not verified", slog.String("user_id", user.ID))
		s.auditLogger.LogAuthAttempt(pkglogger.AuditEvent{
			EventType:     "login_failed",
			UserID:        user.ID,
			FailureReason: "email_not_verified",
			Success:       false,
		})
		return nil, models.ErrEmailNotVerified
	}

	// Verify password
	if err := pkgauth.ComparePassword(user.PasswordHash, password); err != nil {
		s.logger.Info("login failed: invalid credentials")
		s.auditLogger.LogAuthAttempt(pkglogger.AuditEvent{
			EventType:     "login_failed",
			UserID:        user.ID,
			FailureReason: "invalid_credentials",
			Success:       false,
		})
		return nil, models.ErrUnauthorized
	}

	// Generate tokens
	accessToken, err := s.tm.GenerateAccessToken(user.ID, user.Email)
	if err != nil {
		s.logger.Error("failed to generate access token", slog.String("user_id", user.ID), slog.Any("error", err))
		return nil, models.ErrInternalServer
	}

	refreshToken, err := s.tm.GenerateRefreshToken(user.ID, user.Email)
	if err != nil {
		s.logger.Error("failed to generate refresh token", slog.String("user_id", user.ID), slog.Any("error", err))
		return nil, models.ErrInternalServer
	}

	s.logger.Info("user logged in", slog.String("user_id", user.ID))
	s.auditLogger.LogAuthAttempt(pkglogger.AuditEvent{
		EventType: "login_success",
		UserID:    user.ID,
		Success:   true,
	})

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

	s.logger.Info("token refreshed", slog.String("user_id", user.ID))

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
	_, err := s.repo.GetByEmail(ctx, email)
	if err == nil {
		s.logger.Info("registration failed: user already exists")
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

	// Create user
	now := time.Now()
	user := &models.User{
		Email:             email,
		PasswordHash:      hashedPassword,
		Name:              name,
		Role:              "user", // Default role
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

	// Generate tokens
	accessToken, err := s.tm.GenerateAccessToken(createdUser.ID, createdUser.Email)
	if err != nil {
		s.logger.Error("failed to generate access token", slog.String("user_id", createdUser.ID), slog.Any("error", err))
		return nil, models.ErrInternalServer
	}

	refreshToken, err := s.tm.GenerateRefreshToken(createdUser.ID, createdUser.Email)
	if err != nil {
		s.logger.Error("failed to generate refresh token", slog.String("user_id", createdUser.ID), slog.Any("error", err))
		return nil, models.ErrInternalServer
	}

	s.logger.Info("user registered", slog.String("user_id", createdUser.ID))
	s.auditLogger.LogAccountAction("user_registered", createdUser.ID, "", nil)

	return &AuthResponse{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		User:         userModelToResponse(createdUser),
	}, nil
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
