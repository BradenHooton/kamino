package services

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/BradenHooton/kamino/internal/models"
)

// EmailVerificationRepository defines the interface for email verification token operations
type EmailVerificationRepository interface {
	Create(ctx context.Context, userID, tokenHash, email string, expiresAt time.Time) (*models.EmailVerificationToken, error)
	GetByTokenHash(ctx context.Context, tokenHash string) (*models.EmailVerificationToken, error)
	MarkAsUsed(ctx context.Context, id string) error
	DeleteByUserID(ctx context.Context, userID string) error
	CleanupExpired(ctx context.Context) (int64, error)
	GetPendingByEmail(ctx context.Context, email string) (*models.EmailVerificationToken, error)
}

// EmailVerificationService handles email verification business logic
type EmailVerificationService struct {
	emailVerificationRepo EmailVerificationRepository
	userRepo              UserRepository
	emailService          EmailService
	logger                *slog.Logger
	tokenExpiry           time.Duration
	resendCooldown        time.Duration
}

// NewEmailVerificationService creates a new EmailVerificationService
func NewEmailVerificationService(
	emailVerificationRepo EmailVerificationRepository,
	userRepo UserRepository,
	emailService EmailService,
	logger *slog.Logger,
	tokenExpiry time.Duration,
) *EmailVerificationService {
	return &EmailVerificationService{
		emailVerificationRepo: emailVerificationRepo,
		userRepo:              userRepo,
		emailService:          emailService,
		logger:                logger,
		tokenExpiry:           tokenExpiry,
		resendCooldown:        20 * time.Minute, // Prevent spam - must wait 20 min between resends
	}
}

// SendVerificationEmail generates a token and sends a verification email
func (s *EmailVerificationService) SendVerificationEmail(ctx context.Context, userID, email string) error {
	// Generate a random 32-byte token
	tokenBytes := make([]byte, 32)
	if _, err := rand.Read(tokenBytes); err != nil {
		s.logger.Error("failed to generate random token", slog.Any("error", err))
		return fmt.Errorf("failed to generate token: %w", err)
	}

	// Encode to base64 URL-safe format for use in URLs
	plainToken := base64.URLEncoding.EncodeToString(tokenBytes)

	// Hash the token with SHA256 for storage (allows verification by re-hashing)
	hash := sha256.Sum256([]byte(plainToken))
	tokenHash := hex.EncodeToString(hash[:])

	// Calculate expiration time
	expiresAt := time.Now().Add(s.tokenExpiry)

	// Create token record in database
	_, err := s.emailVerificationRepo.Create(ctx, userID, tokenHash, email, expiresAt)
	if err != nil {
		s.logger.Error("failed to create email verification token",
			slog.String("user_id", userID),
			slog.String("email", email),
			slog.Any("error", err))
		return fmt.Errorf("failed to create token: %w", err)
	}

	// Send verification email with plain token
	if err := s.emailService.SendVerificationEmail(ctx, email, plainToken, expiresAt); err != nil {
		s.logger.Error("failed to send verification email",
			slog.String("user_id", userID),
			slog.String("email", email),
			slog.Any("error", err))
		return fmt.Errorf("failed to send email: %w", err)
	}

	s.logger.Info("verification email sent",
		slog.String("user_id", userID),
		slog.String("email", email))

	return nil
}

// VerifyEmail verifies a token and marks the user's email as verified
func (s *EmailVerificationService) VerifyEmail(ctx context.Context, plainToken string) (string, error) {
	if plainToken == "" {
		s.logger.Warn("empty verification token provided")
		return "", models.ErrUnauthorized
	}

	// Hash the provided token with SHA256
	hash := sha256.Sum256([]byte(plainToken))
	tokenHash := hex.EncodeToString(hash[:])

	// Retrieve token from database by hash
	token, err := s.emailVerificationRepo.GetByTokenHash(ctx, tokenHash)
	if err != nil {
		if errors.Is(err, models.ErrNotFound) {
			s.logger.Info("verification token not found or expired")
			return "", models.ErrUnauthorized
		}
		s.logger.Error("failed to retrieve verification token", slog.Any("error", err))
		return "", models.ErrInternalServer
	}

	// Check if token has been used
	if token.IsUsed() {
		s.logger.Warn("attempt to reuse verification token",
			slog.String("token_id", token.ID))
		return "", models.ErrUnauthorized
	}

	// Check if token has expired
	if token.IsExpired() {
		s.logger.Info("verification token expired",
			slog.String("token_id", token.ID),
			slog.Time("expires_at", token.ExpiresAt))
		return "", models.ErrUnauthorized
	}

	// Mark token as used
	if err := s.emailVerificationRepo.MarkAsUsed(ctx, token.ID); err != nil {
		s.logger.Error("failed to mark token as used",
			slog.String("token_id", token.ID),
			slog.Any("error", err))
		return "", models.ErrInternalServer
	}

	// Update user's email verification status
	user, err := s.userRepo.GetByID(ctx, token.UserID)
	if err != nil {
		s.logger.Error("failed to retrieve user for email verification",
			slog.String("user_id", token.UserID),
			slog.Any("error", err))
		return "", models.ErrInternalServer
	}

	user.EmailVerified = true
	_, err = s.userRepo.Update(ctx, token.UserID, user)
	if err != nil {
		s.logger.Error("failed to update user email verification status",
			slog.String("user_id", token.UserID),
			slog.Any("error", err))
		return "", models.ErrInternalServer
	}

	s.logger.Info("email verified successfully",
		slog.String("user_id", token.UserID),
		slog.String("email", token.Email))

	return token.UserID, nil
}

// ResendVerification sends a new verification email if rate limits allow
func (s *EmailVerificationService) ResendVerification(ctx context.Context, email string) error {
	// Anti-enumeration: Always return success even if email doesn't exist
	// But check if there's a pending token that was recently sent

	// Get the most recent pending token for this email
	existingToken, err := s.emailVerificationRepo.GetPendingByEmail(ctx, email)
	if err != nil && !errors.Is(err, models.ErrNotFound) {
		s.logger.Error("failed to check for existing tokens",
			slog.String("email", email),
			slog.Any("error", err))
		// Fail silently to user (anti-enumeration)
		return nil
	}

	// Check if there's a recent token (created within cooldown period)
	if existingToken != nil {
		timeSinceCreation := time.Since(existingToken.CreatedAt)
		if timeSinceCreation < s.resendCooldown {
			s.logger.Info("resend rate limited",
				slog.String("email", email),
				slog.Duration("time_since_last_resend", timeSinceCreation))
			// Return success to prevent enumeration
			return nil
		}

		// Token is too old, delete it before creating a new one
		err = s.emailVerificationRepo.DeleteByUserID(ctx, existingToken.UserID)
		if err != nil {
			s.logger.Error("failed to delete old tokens",
				slog.String("user_id", existingToken.UserID),
				slog.Any("error", err))
			// Continue anyway
		}
	}

	// If no existing token, we can't resend (user doesn't exist or email is already verified)
	// Return success to prevent enumeration
	if existingToken == nil {
		return nil
	}

	// Send new verification email
	return s.SendVerificationEmail(ctx, existingToken.UserID, email)
}

// GetStatus returns the verification status for a user
func (s *EmailVerificationService) GetStatus(ctx context.Context, userID string) (bool, error) {
	user, err := s.userRepo.GetByID(ctx, userID)
	if err != nil {
		return false, err
	}

	return user.EmailVerified, nil
}
