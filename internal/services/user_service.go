package services

import (
	"context"
	"errors"
	"fmt"
	"log/slog"

	"github.com/BradenHooton/kamino/internal/models"
	"github.com/BradenHooton/kamino/pkg/auth"
)

// UserRepository defines the interface for user data access
type UserRepository interface {
	GetByID(ctx context.Context, id string) (*models.User, error)
	List(ctx context.Context, limit, offset int) ([]*models.User, error)
	Create(ctx context.Context, user *models.User) (*models.User, error)
	Update(ctx context.Context, id string, user *models.User) (*models.User, error)
	Delete(ctx context.Context, id string) error
	GetByEmail(ctx context.Context, email string) (*models.User, error)
}

// UserService handles user business logic
type UserService struct {
	repo   UserRepository
	logger *slog.Logger
}

// NewUserService creates a new UserService
func NewUserService(repo UserRepository, logger *slog.Logger) *UserService {
	return &UserService{
		repo:   repo,
		logger: logger,
	}
}

// GetUserByID retrieves a user by ID
func (s *UserService) GetUserByID(id string) (*models.User, error) {
	ctx := context.Background()

	user, err := s.repo.GetByID(ctx, id)
	if err != nil {
		if errors.Is(err, models.ErrNotFound) {
			s.logger.Info("user not found", slog.String("user_id", id))
			return nil, models.ErrNotFound
		}
		s.logger.Error("failed to get user", slog.String("user_id", id), slog.Any("error", err))
		return nil, models.ErrInternalServer
	}

	return user, nil
}

// ListUsers retrieves a list of users with pagination
func (s *UserService) ListUsers(limit, offset int) ([]*models.User, error) {
	ctx := context.Background()

	users, err := s.repo.List(ctx, limit, offset)
	if err != nil {
		s.logger.Error("failed to list users", slog.Int("limit", limit), slog.Int("offset", offset), slog.Any("error", err))
		return nil, models.ErrInternalServer
	}

	return users, nil
}

// CreateUser creates a new user
func (s *UserService) CreateUser(user *models.User, password string) (*models.User, error) {
	ctx := context.Background()

	// Check if user already exists
	existingUser, err := s.repo.GetByEmail(ctx, user.Email)
	if err == nil && existingUser != nil {
		s.logger.Info("user already exists")
		return nil, models.ErrConflict
	}

	// Hash password if provided
	if password != "" {
		if err := auth.ValidatePassword(password); err != nil {
			return nil, fmt.Errorf("invalid password: %w", err)
		}

		hashedPassword, err := auth.HashPassword(password)
		if err != nil {
			s.logger.Error("failed to hash password", slog.Any("error", err))
			return nil, models.ErrInternalServer
		}
		user.PasswordHash = hashedPassword
	}

	// Create user
	createdUser, err := s.repo.Create(ctx, user)
	if err != nil {
		s.logger.Error("failed to create user", slog.Any("error", err))
		return nil, models.ErrInternalServer
	}

	s.logger.Info("user created", slog.String("user_id", createdUser.ID))
	return createdUser, nil
}

// UpdateUser updates an existing user
func (s *UserService) UpdateUser(id string, user *models.User) (*models.User, error) {
	ctx := context.Background()

	// Check if user exists
	existingUser, err := s.repo.GetByID(ctx, id)
	if err != nil {
		if errors.Is(err, models.ErrNotFound) {
			s.logger.Info("user not found", slog.String("user_id", id))
			return nil, models.ErrNotFound
		}
		s.logger.Error("failed to get user", slog.String("user_id", id), slog.Any("error", err))
		return nil, models.ErrInternalServer
	}

	// Apply updates only to non-zero fields
	if user.Name != "" {
		existingUser.Name = user.Name
	}
	if user.Role != "" {
		existingUser.Role = user.Role
	}

	// Update user
	updatedUser, err := s.repo.Update(ctx, id, existingUser)
	if err != nil {
		s.logger.Error("failed to update user", slog.String("user_id", id), slog.Any("error", err))
		return nil, models.ErrInternalServer
	}

	s.logger.Info("user updated", slog.String("user_id", id))
	return updatedUser, nil
}

// DeleteUser deletes a user
func (s *UserService) DeleteUser(id string) error {
	ctx := context.Background()

	// Check if user exists
	_, err := s.repo.GetByID(ctx, id)
	if err != nil {
		if errors.Is(err, models.ErrNotFound) {
			s.logger.Info("user not found", slog.String("user_id", id))
			return models.ErrNotFound
		}
		s.logger.Error("failed to get user", slog.String("user_id", id), slog.Any("error", err))
		return models.ErrInternalServer
	}

	// Delete user
	err = s.repo.Delete(ctx, id)
	if err != nil {
		s.logger.Error("failed to delete user", slog.String("user_id", id), slog.Any("error", err))
		return models.ErrInternalServer
	}

	s.logger.Info("user deleted", slog.String("user_id", id))
	return nil
}
