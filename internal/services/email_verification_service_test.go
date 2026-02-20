package services

import (
	"context"
	"log/slog"
	"testing"
	"time"

	"github.com/BradenHooton/kamino/internal/models"
	"github.com/stretchr/testify/assert"
)

func TestEmailVerificationService_SendVerificationEmail_Success(t *testing.T) {
	mockEmailVerifRepo := &MockEmailVerificationRepository{
		CreateFunc: func(ctx context.Context, userID, tokenHash, email string, expiresAt time.Time) (*models.EmailVerificationToken, error) {
			return &models.EmailVerificationToken{
				ID:        "token_123",
				UserID:    userID,
				Email:     email,
				ExpiresAt: expiresAt,
				CreatedAt: time.Now(),
			}, nil
		},
	}

	mockUserRepo := &MockUserRepository{}

	emailSent := false
	mockEmailService := &MockEmailService{
		SendVerificationEmailFunc: func(ctx context.Context, email, token string, expiresAt time.Time) error {
			emailSent = true
			return nil
		},
	}

	logger := slog.Default()
	svc := NewEmailVerificationService(mockEmailVerifRepo, mockUserRepo, mockEmailService, logger, 24*time.Hour)

	err := svc.SendVerificationEmail(context.Background(), "user123", "user@example.com")

	assert.NoError(t, err)
	assert.True(t, emailSent, "email should have been sent")
}

func TestEmailVerificationService_SendVerificationEmail_TokenCreationFails(t *testing.T) {
	mockEmailVerifRepo := &MockEmailVerificationRepository{
		CreateFunc: func(ctx context.Context, userID, tokenHash, email string, expiresAt time.Time) (*models.EmailVerificationToken, error) {
			return nil, models.ErrInternalServer
		},
	}

	mockUserRepo := &MockUserRepository{}
	mockEmailService := &MockEmailService{}

	logger := slog.Default()
	svc := NewEmailVerificationService(mockEmailVerifRepo, mockUserRepo, mockEmailService, logger, 24*time.Hour)

	err := svc.SendVerificationEmail(context.Background(), "user123", "user@example.com")

	assert.Error(t, err)
}

func TestEmailVerificationService_SendVerificationEmail_EmailSendFails(t *testing.T) {
	mockEmailVerifRepo := &MockEmailVerificationRepository{
		CreateFunc: func(ctx context.Context, userID, tokenHash, email string, expiresAt time.Time) (*models.EmailVerificationToken, error) {
			return &models.EmailVerificationToken{
				ID:     "token_123",
				UserID: userID,
				Email:  email,
			}, nil
		},
	}

	mockUserRepo := &MockUserRepository{}
	mockEmailService := &MockEmailService{
		SendVerificationEmailFunc: func(ctx context.Context, email, token string, expiresAt time.Time) error {
			return models.ErrInternalServer
		},
	}

	logger := slog.Default()
	svc := NewEmailVerificationService(mockEmailVerifRepo, mockUserRepo, mockEmailService, logger, 24*time.Hour)

	err := svc.SendVerificationEmail(context.Background(), "user123", "user@example.com")

	// Should still fail if email send fails
	assert.Error(t, err)
}

func TestEmailVerificationService_VerifyEmail_Success(t *testing.T) {
	plainToken := "test_verification_token_123"

	token := NewTestEmailVerificationToken("token_123", "user123", "user@example.com", time.Now().Add(24*time.Hour))

	mockEmailVerifRepo := &MockEmailVerificationRepository{
		GetByTokenHashFunc: func(ctx context.Context, hash string) (*models.EmailVerificationToken, error) {
			return token, nil
		},
		MarkAsUsedFunc: func(ctx context.Context, id string) error {
			token.UsedAt = timePtr(time.Now())
			return nil
		},
	}

	user := NewTestUserUnverified("user123", "user@example.com", "Test User")
	mockUserRepo := &MockUserRepository{
		GetByIDFunc: func(ctx context.Context, id string) (*models.User, error) {
			return user, nil
		},
		UpdateFunc: func(ctx context.Context, id string, u *models.User) (*models.User, error) {
			user.EmailVerified = true
			return user, nil
		},
	}

	mockEmailService := &MockEmailService{}

	logger := slog.Default()
	svc := NewEmailVerificationService(mockEmailVerifRepo, mockUserRepo, mockEmailService, logger, 24*time.Hour)

	userID, err := svc.VerifyEmail(context.Background(), plainToken)

	assert.NoError(t, err)
	assert.Equal(t, "user123", userID)
}

func TestEmailVerificationService_VerifyEmail_InvalidToken(t *testing.T) {
	mockEmailVerifRepo := &MockEmailVerificationRepository{
		GetByTokenHashFunc: func(ctx context.Context, hash string) (*models.EmailVerificationToken, error) {
			return nil, models.ErrNotFound
		},
	}

	mockUserRepo := &MockUserRepository{}
	mockEmailService := &MockEmailService{}

	logger := slog.Default()
	svc := NewEmailVerificationService(mockEmailVerifRepo, mockUserRepo, mockEmailService, logger, 24*time.Hour)

	userID, err := svc.VerifyEmail(context.Background(), "invalid_token")

	assert.Error(t, err)
	assert.Equal(t, "", userID)
	assert.Equal(t, models.ErrUnauthorized, err)
}

func TestEmailVerificationService_VerifyEmail_EmptyToken(t *testing.T) {
	mockEmailVerifRepo := &MockEmailVerificationRepository{}
	mockUserRepo := &MockUserRepository{}
	mockEmailService := &MockEmailService{}

	logger := slog.Default()
	svc := NewEmailVerificationService(mockEmailVerifRepo, mockUserRepo, mockEmailService, logger, 24*time.Hour)

	userID, err := svc.VerifyEmail(context.Background(), "")

	assert.Error(t, err)
	assert.Equal(t, "", userID)
	assert.Equal(t, models.ErrUnauthorized, err)
}

func TestEmailVerificationService_VerifyEmail_ExpiredToken(t *testing.T) {
	plainToken := "expired_token"

	// Create expired token (expires 1 hour ago)
	token := NewTestEmailVerificationTokenExpired("token_123", "user123", "user@example.com")

	mockEmailVerifRepo := &MockEmailVerificationRepository{
		GetByTokenHashFunc: func(ctx context.Context, hash string) (*models.EmailVerificationToken, error) {
			return token, nil
		},
	}

	mockUserRepo := &MockUserRepository{}
	mockEmailService := &MockEmailService{}

	logger := slog.Default()
	svc := NewEmailVerificationService(mockEmailVerifRepo, mockUserRepo, mockEmailService, logger, 24*time.Hour)

	userID, err := svc.VerifyEmail(context.Background(), plainToken)

	assert.Error(t, err)
	assert.Equal(t, "", userID)
	assert.Equal(t, models.ErrUnauthorized, err)
}

func TestEmailVerificationService_VerifyEmail_AlreadyUsedToken(t *testing.T) {
	plainToken := "used_token"

	// Create used token
	token := NewTestEmailVerificationTokenUsed("token_123", "user123", "user@example.com")

	mockEmailVerifRepo := &MockEmailVerificationRepository{
		GetByTokenHashFunc: func(ctx context.Context, hash string) (*models.EmailVerificationToken, error) {
			return token, nil
		},
	}

	mockUserRepo := &MockUserRepository{}
	mockEmailService := &MockEmailService{}

	logger := slog.Default()
	svc := NewEmailVerificationService(mockEmailVerifRepo, mockUserRepo, mockEmailService, logger, 24*time.Hour)

	userID, err := svc.VerifyEmail(context.Background(), plainToken)

	assert.Error(t, err)
	assert.Equal(t, "", userID)
	assert.Equal(t, models.ErrUnauthorized, err)
}

func TestEmailVerificationService_ResendVerification_ExistingTokenWithinCooldown(t *testing.T) {
	// Token created 5 minutes ago (within 20 minute cooldown)
	recentToken := NewTestEmailVerificationToken("token_123", "user123", "user@example.com", time.Now().Add(24*time.Hour))
	recentToken.CreatedAt = time.Now().Add(-5 * time.Minute)

	mockEmailVerifRepo := &MockEmailVerificationRepository{
		GetPendingByEmailFunc: func(ctx context.Context, email string) (*models.EmailVerificationToken, error) {
			return recentToken, nil
		},
	}

	mockUserRepo := &MockUserRepository{}
	mockEmailService := &MockEmailService{}

	logger := slog.Default()
	svc := NewEmailVerificationService(mockEmailVerifRepo, mockUserRepo, mockEmailService, logger, 24*time.Hour)

	err := svc.ResendVerification(context.Background(), "user@example.com")

	// Should return success (anti-enumeration) even though we don't actually send
	assert.NoError(t, err)
}

func TestEmailVerificationService_ResendVerification_ExistingTokenOutsideCooldown(t *testing.T) {
	// Token created 30 minutes ago (outside 20 minute cooldown)
	oldToken := NewTestEmailVerificationToken("token_123", "user123", "user@example.com", time.Now().Add(24*time.Hour))
	oldToken.CreatedAt = time.Now().Add(-30 * time.Minute)

	mockEmailVerifRepo := &MockEmailVerificationRepository{
		GetPendingByEmailFunc: func(ctx context.Context, email string) (*models.EmailVerificationToken, error) {
			return oldToken, nil
		},
		DeleteByUserIDFunc: func(ctx context.Context, userID string) error {
			return nil
		},
		CreateFunc: func(ctx context.Context, userID, tokenHash, email string, expiresAt time.Time) (*models.EmailVerificationToken, error) {
			return &models.EmailVerificationToken{
				ID:     "new_token",
				UserID: userID,
				Email:  email,
			}, nil
		},
	}

	mockUserRepo := &MockUserRepository{}

	emailSent := false
	mockEmailService := &MockEmailService{
		SendVerificationEmailFunc: func(ctx context.Context, email, token string, expiresAt time.Time) error {
			emailSent = true
			return nil
		},
	}

	logger := slog.Default()
	svc := NewEmailVerificationService(mockEmailVerifRepo, mockUserRepo, mockEmailService, logger, 24*time.Hour)

	err := svc.ResendVerification(context.Background(), "user@example.com")

	assert.NoError(t, err)
	assert.True(t, emailSent, "new email should have been sent")
}

func TestEmailVerificationService_ResendVerification_NoExistingToken(t *testing.T) {
	// User doesn't exist or already verified
	mockEmailVerifRepo := &MockEmailVerificationRepository{
		GetPendingByEmailFunc: func(ctx context.Context, email string) (*models.EmailVerificationToken, error) {
			return nil, models.ErrNotFound
		},
	}

	mockUserRepo := &MockUserRepository{}
	mockEmailService := &MockEmailService{}

	logger := slog.Default()
	svc := NewEmailVerificationService(mockEmailVerifRepo, mockUserRepo, mockEmailService, logger, 24*time.Hour)

	err := svc.ResendVerification(context.Background(), "nonexistent@example.com")

	// Should return success (anti-enumeration)
	assert.NoError(t, err)
}

func TestEmailVerificationService_GetStatus_Verified(t *testing.T) {
	user := NewTestUser("user123", "user@example.com", "Test User")
	user.EmailVerified = true

	mockEmailVerifRepo := &MockEmailVerificationRepository{}
	mockUserRepo := &MockUserRepository{
		GetByIDFunc: func(ctx context.Context, id string) (*models.User, error) {
			return user, nil
		},
	}
	mockEmailService := &MockEmailService{}

	logger := slog.Default()
	svc := NewEmailVerificationService(mockEmailVerifRepo, mockUserRepo, mockEmailService, logger, 24*time.Hour)

	verified, err := svc.GetStatus(context.Background(), "user123")

	assert.NoError(t, err)
	assert.True(t, verified)
}

func TestEmailVerificationService_GetStatus_NotVerified(t *testing.T) {
	user := NewTestUserUnverified("user123", "user@example.com", "Test User")

	mockEmailVerifRepo := &MockEmailVerificationRepository{}
	mockUserRepo := &MockUserRepository{
		GetByIDFunc: func(ctx context.Context, id string) (*models.User, error) {
			return user, nil
		},
	}
	mockEmailService := &MockEmailService{}

	logger := slog.Default()
	svc := NewEmailVerificationService(mockEmailVerifRepo, mockUserRepo, mockEmailService, logger, 24*time.Hour)

	verified, err := svc.GetStatus(context.Background(), "user123")

	assert.NoError(t, err)
	assert.False(t, verified)
}

func TestEmailVerificationService_GetStatus_UserNotFound(t *testing.T) {
	mockEmailVerifRepo := &MockEmailVerificationRepository{}
	mockUserRepo := &MockUserRepository{
		GetByIDFunc: func(ctx context.Context, id string) (*models.User, error) {
			return nil, models.ErrNotFound
		},
	}
	mockEmailService := &MockEmailService{}

	logger := slog.Default()
	svc := NewEmailVerificationService(mockEmailVerifRepo, mockUserRepo, mockEmailService, logger, 24*time.Hour)

	verified, err := svc.GetStatus(context.Background(), "nonexistent")

	assert.Error(t, err)
	assert.False(t, verified)
}

// Helper functions for tests

func timePtr(t time.Time) *time.Time {
	return &t
}
