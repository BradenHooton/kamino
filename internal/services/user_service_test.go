package services

import (
	"context"
	"log/slog"
	"testing"
	"time"

	"github.com/BradenHooton/kamino/internal/models"
	"github.com/stretchr/testify/assert"
)

func TestUserService_GetUserByID_Success(t *testing.T) {
	user := NewTestUser("user123", "user@example.com", "Test User")

	mockUserRepo := &MockUserRepository{
		GetByIDFunc: func(ctx context.Context, id string) (*models.User, error) {
			return user, nil
		},
	}

	logger := slog.Default()
	svc := NewUserService(mockUserRepo, logger)

	result, err := svc.GetUserByID("user123")

	assert.NoError(t, err)
	assert.NotNil(t, result)
	assert.Equal(t, "user123", result.ID)
	assert.Equal(t, "user@example.com", result.Email)
}

func TestUserService_GetUserByID_NotFound(t *testing.T) {
	mockUserRepo := &MockUserRepository{
		GetByIDFunc: func(ctx context.Context, id string) (*models.User, error) {
			return nil, models.ErrNotFound
		},
	}

	logger := slog.Default()
	svc := NewUserService(mockUserRepo, logger)

	result, err := svc.GetUserByID("nonexistent")

	assert.Error(t, err)
	assert.Nil(t, result)
	assert.Equal(t, models.ErrNotFound, err)
}

func TestUserService_GetUserByID_DatabaseError(t *testing.T) {
	mockUserRepo := &MockUserRepository{
		GetByIDFunc: func(ctx context.Context, id string) (*models.User, error) {
			return nil, models.ErrInternalServer
		},
	}

	logger := slog.Default()
	svc := NewUserService(mockUserRepo, logger)

	result, err := svc.GetUserByID("user123")

	assert.Error(t, err)
	assert.Nil(t, result)
	assert.Equal(t, models.ErrInternalServer, err)
}

func TestUserService_ListUsers_Success(t *testing.T) {
	users := []*models.User{
		NewTestUser("user1", "user1@example.com", "User One"),
		NewTestUser("user2", "user2@example.com", "User Two"),
	}

	mockUserRepo := &MockUserRepository{
		ListFunc: func(ctx context.Context, limit, offset int) ([]*models.User, error) {
			return users, nil
		},
	}

	logger := slog.Default()
	svc := NewUserService(mockUserRepo, logger)

	result, err := svc.ListUsers(10, 0)

	assert.NoError(t, err)
	assert.Len(t, result, 2)
	assert.Equal(t, "user1", result[0].ID)
	assert.Equal(t, "user2", result[1].ID)
}

func TestUserService_ListUsers_Empty(t *testing.T) {
	mockUserRepo := &MockUserRepository{
		ListFunc: func(ctx context.Context, limit, offset int) ([]*models.User, error) {
			return []*models.User{}, nil
		},
	}

	logger := slog.Default()
	svc := NewUserService(mockUserRepo, logger)

	result, err := svc.ListUsers(10, 0)

	assert.NoError(t, err)
	assert.Len(t, result, 0)
}

func TestUserService_ListUsers_DatabaseError(t *testing.T) {
	mockUserRepo := &MockUserRepository{
		ListFunc: func(ctx context.Context, limit, offset int) ([]*models.User, error) {
			return nil, models.ErrInternalServer
		},
	}

	logger := slog.Default()
	svc := NewUserService(mockUserRepo, logger)

	result, err := svc.ListUsers(10, 0)

	assert.Error(t, err)
	assert.Nil(t, result)
	assert.Equal(t, models.ErrInternalServer, err)
}

func TestUserService_CreateUser_Success(t *testing.T) {
	newUser := NewTestUser("", "newuser@example.com", "New User")

	mockUserRepo := &MockUserRepository{
		GetByEmailFunc: func(ctx context.Context, email string) (*models.User, error) {
			return nil, models.ErrNotFound
		},
		CreateFunc: func(ctx context.Context, user *models.User) (*models.User, error) {
			user.ID = "new_user_123"
			user.CreatedAt = time.Now()
			user.UpdatedAt = time.Now()
			return user, nil
		},
	}

	logger := slog.Default()
	svc := NewUserService(mockUserRepo, logger)

	result, err := svc.CreateUser(newUser, "SecurePassword123!")

	assert.NoError(t, err)
	assert.NotNil(t, result)
	assert.Equal(t, "new_user_123", result.ID)
	assert.NotEmpty(t, result.PasswordHash) // Password should be hashed
}

func TestUserService_CreateUser_DuplicateEmail(t *testing.T) {
	existingUser := NewTestUser("existing_user", "taken@example.com", "Existing User")
	newUser := NewTestUser("", "taken@example.com", "New User")

	mockUserRepo := &MockUserRepository{
		GetByEmailFunc: func(ctx context.Context, email string) (*models.User, error) {
			return existingUser, nil
		},
	}

	logger := slog.Default()
	svc := NewUserService(mockUserRepo, logger)

	result, err := svc.CreateUser(newUser, "SecurePassword123!")

	assert.Error(t, err)
	assert.Nil(t, result)
	assert.Equal(t, models.ErrConflict, err)
}

func TestUserService_CreateUser_InvalidPassword(t *testing.T) {
	newUser := NewTestUser("", "newuser@example.com", "New User")

	mockUserRepo := &MockUserRepository{
		GetByEmailFunc: func(ctx context.Context, email string) (*models.User, error) {
			return nil, models.ErrNotFound
		},
	}

	logger := slog.Default()
	svc := NewUserService(mockUserRepo, logger)

	// Weak password
	result, err := svc.CreateUser(newUser, "weak")

	assert.Error(t, err)
	assert.Nil(t, result)
}

func TestUserService_CreateUser_NoPassword(t *testing.T) {
	newUser := NewTestUser("", "newuser@example.com", "New User")

	mockUserRepo := &MockUserRepository{
		GetByEmailFunc: func(ctx context.Context, email string) (*models.User, error) {
			return nil, models.ErrNotFound
		},
		CreateFunc: func(ctx context.Context, user *models.User) (*models.User, error) {
			user.ID = "new_user_123"
			return user, nil
		},
	}

	logger := slog.Default()
	svc := NewUserService(mockUserRepo, logger)

	// Empty password should be allowed (admin creating user without password)
	result, err := svc.CreateUser(newUser, "")

	assert.NoError(t, err)
	assert.NotNil(t, result)
	assert.Empty(t, result.PasswordHash)
}

func TestUserService_UpdateUser_Success(t *testing.T) {
	existingUser := NewTestUser("user123", "user@example.com", "Old Name")
	updatedUser := &models.User{
		ID:   "user123",
		Name: "New Name",
	}

	mockUserRepo := &MockUserRepository{
		GetByIDFunc: func(ctx context.Context, id string) (*models.User, error) {
			return existingUser, nil
		},
		UpdateFunc: func(ctx context.Context, id string, user *models.User) (*models.User, error) {
			existingUser.Name = user.Name
			return existingUser, nil
		},
	}

	logger := slog.Default()
	svc := NewUserService(mockUserRepo, logger)

	result, err := svc.UpdateUser("user123", updatedUser)

	assert.NoError(t, err)
	assert.NotNil(t, result)
	assert.Equal(t, "New Name", result.Name)
}

func TestUserService_UpdateUser_NotFound(t *testing.T) {
	updatedUser := &models.User{
		ID:   "nonexistent",
		Name: "New Name",
	}

	mockUserRepo := &MockUserRepository{
		GetByIDFunc: func(ctx context.Context, id string) (*models.User, error) {
			return nil, models.ErrNotFound
		},
	}

	logger := slog.Default()
	svc := NewUserService(mockUserRepo, logger)

	result, err := svc.UpdateUser("nonexistent", updatedUser)

	assert.Error(t, err)
	assert.Nil(t, result)
	assert.Equal(t, models.ErrNotFound, err)
}

func TestUserService_UpdateUser_PartialFields(t *testing.T) {
	existingUser := NewTestUser("user123", "user@example.com", "Original Name")
	existingUser.Role = "user"

	// Update with only Name (Role should remain unchanged)
	updatedUser := &models.User{
		ID:   "user123",
		Name: "Updated Name",
	}

	mockUserRepo := &MockUserRepository{
		GetByIDFunc: func(ctx context.Context, id string) (*models.User, error) {
			return existingUser, nil
		},
		UpdateFunc: func(ctx context.Context, id string, user *models.User) (*models.User, error) {
			if user.Name != "" {
				existingUser.Name = user.Name
			}
			return existingUser, nil
		},
	}

	logger := slog.Default()
	svc := NewUserService(mockUserRepo, logger)

	result, err := svc.UpdateUser("user123", updatedUser)

	assert.NoError(t, err)
	assert.Equal(t, "Updated Name", result.Name)
	assert.Equal(t, "user", result.Role) // Role unchanged
}

func TestUserService_UpdateUser_DatabaseError(t *testing.T) {
	existingUser := NewTestUser("user123", "user@example.com", "Original Name")
	updatedUser := &models.User{
		ID:   "user123",
		Name: "New Name",
	}

	mockUserRepo := &MockUserRepository{
		GetByIDFunc: func(ctx context.Context, id string) (*models.User, error) {
			return existingUser, nil
		},
		UpdateFunc: func(ctx context.Context, id string, user *models.User) (*models.User, error) {
			return nil, models.ErrInternalServer
		},
	}

	logger := slog.Default()
	svc := NewUserService(mockUserRepo, logger)

	result, err := svc.UpdateUser("user123", updatedUser)

	assert.Error(t, err)
	assert.Nil(t, result)
	assert.Equal(t, models.ErrInternalServer, err)
}

func TestUserService_DeleteUser_Success(t *testing.T) {
	user := NewTestUser("user123", "user@example.com", "Test User")

	mockUserRepo := &MockUserRepository{
		GetByIDFunc: func(ctx context.Context, id string) (*models.User, error) {
			return user, nil
		},
		DeleteFunc: func(ctx context.Context, id string) error {
			return nil
		},
	}

	logger := slog.Default()
	svc := NewUserService(mockUserRepo, logger)

	err := svc.DeleteUser("user123")

	assert.NoError(t, err)
}

func TestUserService_DeleteUser_NotFound(t *testing.T) {
	mockUserRepo := &MockUserRepository{
		GetByIDFunc: func(ctx context.Context, id string) (*models.User, error) {
			return nil, models.ErrNotFound
		},
	}

	logger := slog.Default()
	svc := NewUserService(mockUserRepo, logger)

	err := svc.DeleteUser("nonexistent")

	assert.Error(t, err)
	assert.Equal(t, models.ErrNotFound, err)
}

func TestUserService_DeleteUser_DatabaseError(t *testing.T) {
	user := NewTestUser("user123", "user@example.com", "Test User")

	mockUserRepo := &MockUserRepository{
		GetByIDFunc: func(ctx context.Context, id string) (*models.User, error) {
			return user, nil
		},
		DeleteFunc: func(ctx context.Context, id string) error {
			return models.ErrInternalServer
		},
	}

	logger := slog.Default()
	svc := NewUserService(mockUserRepo, logger)

	err := svc.DeleteUser("user123")

	assert.Error(t, err)
	assert.Equal(t, models.ErrInternalServer, err)
}
