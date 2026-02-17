package repositories

import (
	"context"

	"github.com/BradenHooton/kamino/internal/models"
)

type OTPRepository interface {
    Create(ctx context.Context, otp *models.OTP) error
    FindByID(ctx context.Context, id string) (*models.OTP, error)
    Delete(ctx context.Context, id string) error
    DeleteExpired(ctx context.Context) error
}

type ExternalAuthRepository interface {
	// TODO:
}

type MFARepository interface {
	// TODO:
}
