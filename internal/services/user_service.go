package services

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/BradenHooton/kamino/internal/models"
	"github.com/BradenHooton/kamino/pkg/auth"
	"github.com/google/uuid"
)

// UserRepository defines the interface for user data access
type UserRepository interface {
	GetByID(ctx context.Context, id string) (*models.User, error)
	List(ctx context.Context, limit, offset int) ([]*models.User, error)
	Create(ctx context.Context, user *models.User) (*models.User, error)
	Update(ctx context.Context, id string, user *models.User) (*models.User, error)
	Delete(ctx context.Context, id string) error
	GetByEmail(ctx context.Context, email string) (*models.User, error)
	UpdateStatus(ctx context.Context, id, status string) error
	LockAccount(ctx context.Context, id string, lockedUntil *time.Time) error
	Search(ctx context.Context, criteria models.SearchCriteria) ([]*models.User, int64, error)
}

// UserService handles user business logic
type UserService struct {
	repo         UserRepository
	auditService *AuditService
	logger       *slog.Logger
}

// NewUserService creates a new UserService
func NewUserService(repo UserRepository, auditService *AuditService, logger *slog.Logger) *UserService {
	return &UserService{
		repo:         repo,
		auditService: auditService,
		logger:       logger,
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

// SuspendUser sets a user's status to "suspended" and emits an audit event.
// actorID must differ from id (admins cannot suspend themselves).
func (s *UserService) SuspendUser(id, reason, actorID string) error {
	ctx := context.Background()
	if id == actorID {
		return models.ErrForbidden
	}
	if _, err := s.repo.GetByID(ctx, id); err != nil {
		return err
	}
	if err := s.repo.UpdateStatus(ctx, id, "suspended"); err != nil {
		s.logger.Error("failed to suspend user", slog.String("user_id", id), slog.Any("error", err))
		return models.ErrInternalServer
	}
	s.emitStatusChangeAudit(ctx, models.AuditEventTypeUserSuspended, actorID, id, reason, "suspended")
	s.logger.Info("user suspended", slog.String("user_id", id), slog.String("actor_id", actorID))
	return nil
}

// ActivateUser sets a user's status to "active" and emits an audit event.
func (s *UserService) ActivateUser(id, reason, actorID string) error {
	ctx := context.Background()
	if id == actorID {
		return models.ErrForbidden
	}
	if _, err := s.repo.GetByID(ctx, id); err != nil {
		return err
	}
	if err := s.repo.UpdateStatus(ctx, id, "active"); err != nil {
		s.logger.Error("failed to activate user", slog.String("user_id", id), slog.Any("error", err))
		return models.ErrInternalServer
	}
	s.emitStatusChangeAudit(ctx, models.AuditEventTypeUserActivated, actorID, id, reason, "active")
	s.logger.Info("user activated", slog.String("user_id", id), slog.String("actor_id", actorID))
	return nil
}

// DisableUser permanently disables an account.
func (s *UserService) DisableUser(id, reason, actorID string) error {
	ctx := context.Background()
	if id == actorID {
		return models.ErrForbidden
	}
	if _, err := s.repo.GetByID(ctx, id); err != nil {
		return err
	}
	if err := s.repo.UpdateStatus(ctx, id, "disabled"); err != nil {
		s.logger.Error("failed to disable user", slog.String("user_id", id), slog.Any("error", err))
		return models.ErrInternalServer
	}
	s.emitStatusChangeAudit(ctx, models.AuditEventTypeUserSuspended, actorID, id, reason, "disabled")
	s.logger.Info("user disabled", slog.String("user_id", id), slog.String("actor_id", actorID))
	return nil
}

// LockUser sets a temporary account lock for the given duration (5m–24h).
func (s *UserService) LockUser(id string, duration time.Duration, reason, actorID string) error {
	ctx := context.Background()
	if id == actorID {
		return models.ErrForbidden
	}
	const minDuration = 5 * time.Minute
	const maxDuration = 24 * time.Hour
	if duration < minDuration || duration > maxDuration {
		return fmt.Errorf("%w: duration must be between 5m and 24h", models.ErrBadRequest)
	}
	if _, err := s.repo.GetByID(ctx, id); err != nil {
		return err
	}
	lockedUntil := time.Now().Add(duration)
	if err := s.repo.LockAccount(ctx, id, &lockedUntil); err != nil {
		s.logger.Error("failed to lock user", slog.String("user_id", id), slog.Any("error", err))
		return models.ErrInternalServer
	}
	s.emitStatusChangeAudit(ctx, models.AuditEventTypeUserLocked, actorID, id, reason, models.AuditMetadata{
		"locked_until":     lockedUntil.Format(time.RFC3339),
		"duration_seconds": duration.Seconds(),
	})
	s.logger.Info("user locked", slog.String("user_id", id), slog.String("actor_id", actorID), slog.Duration("duration", duration))
	return nil
}

// UpdateUserStatus is the unified entry point called by the handler, dispatching to
// Suspend/Activate/Disable based on the requested status string.
func (s *UserService) UpdateUserStatus(id, status, reason, actorID string) error {
	switch status {
	case "suspended":
		return s.SuspendUser(id, reason, actorID)
	case "active":
		return s.ActivateUser(id, reason, actorID)
	case "disabled":
		return s.DisableUser(id, reason, actorID)
	default:
		return fmt.Errorf("%w: invalid status %q", models.ErrBadRequest, status)
	}
}

// SearchUsers searches users by the given criteria, returning matches and total count.
func (s *UserService) SearchUsers(criteria models.SearchCriteria) ([]*models.User, int64, error) {
	ctx := context.Background()
	if criteria.Limit <= 0 {
		criteria.Limit = 20
	}
	if criteria.Limit > 100 {
		criteria.Limit = 100
	}
	users, total, err := s.repo.Search(ctx, criteria)
	if err != nil {
		s.logger.Error("failed to search users", slog.Any("error", err))
		return nil, 0, models.ErrInternalServer
	}
	return users, total, nil
}

// emitStatusChangeAudit is a helper that emits an audit log if the audit service is available.
// metadata may be either models.AuditMetadata or a string (new status value).
func (s *UserService) emitStatusChangeAudit(ctx context.Context, eventType, actorID, targetID, reason string, metadata interface{}) {
	if s.auditService == nil {
		return
	}
	actorUUID, err := uuid.Parse(actorID)
	if err != nil {
		return
	}
	targetUUID, err := uuid.Parse(targetID)
	if err != nil {
		return
	}
	var md models.AuditMetadata
	switch v := metadata.(type) {
	case models.AuditMetadata:
		md = v
	case string:
		md = models.AuditMetadata{"new_status": v}
	default:
		md = make(models.AuditMetadata)
	}
	_ = s.auditService.LogStatusChange(ctx, eventType, actorUUID, targetUUID, reason, md)
}
