package handlers_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/BradenHooton/kamino/internal/auth"
	"github.com/BradenHooton/kamino/internal/handlers"
	"github.com/BradenHooton/kamino/internal/models"
	"github.com/go-chi/chi/v5"
	"github.com/stretchr/testify/assert"
)

// CRITICAL SECURITY TEST #1: Privilege Escalation
// Verify that regular users CANNOT change their own role to admin

func TestUpdateUser_PrivilegeEscalation_UserCannotChangeOwnRole(t *testing.T) {
	userID := "user123"

	mockService := &handlers.MockUserService{
		GetUserByIDFunc: func(id string) (*models.User, error) {
			if id == userID {
				return &models.User{
					ID:        userID,
					Email:     "user@example.com",
					Name:      "Regular User",
					Role:      "user",
					CreatedAt: time.Now(),
					UpdatedAt: time.Now(),
				}, nil
			}
			return nil, models.ErrNotFound
		},
		UpdateUserFunc: func(id string, user *models.User) (*models.User, error) {
			t.Fatal("UpdateUserFunc should not be called when authorization fails")
			return nil, nil
		},
	}

	handler := handlers.NewUserHandler(mockService)

	// Prepare request: user tries to change their own role to admin
	reqBody := handlers.UpdateUserRequest{
		Name: "Regular User",
		Role: "admin",
	}
	bodyBytes, _ := json.Marshal(reqBody)
	req := httptest.NewRequest("PUT", "/users/"+userID, bytes.NewReader(bodyBytes))
	req.Header.Set("Content-Type", "application/json")

	// Add auth context as regular user
	claims := &models.TokenClaims{
		UserID: userID,
		Email:  "user@example.com",
		Type:   "access",
	}
	ctx := context.WithValue(req.Context(), auth.UserContextKey, claims)
	req = req.WithContext(ctx)

	// ✅ Add chi route context to set the {id} URL parameter
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("id", userID)
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))

	w := httptest.NewRecorder()
	handler.UpdateUser(w, req)

	// User should get 403 Forbidden when trying to change their own role
	handlers.AssertErrorResponse(t, w, 403, "forbidden")
	assert.Contains(t, w.Body.String(), "role", "Error message should mention role change")
}

// CRITICAL SECURITY TEST #1b: Privilege Escalation
// Verify that admins CANNOT change their own role to something else

func TestUpdateUser_PrivilegeEscalation_AdminCannotChangeOwnRole(t *testing.T) {
	adminID := "admin123"

	mockService := &handlers.MockUserService{
		GetUserByIDFunc: func(id string) (*models.User, error) {
			if id == adminID {
				return &models.User{
					ID:        adminID,
					Email:     "admin@example.com",
					Name:      "Admin User",
					Role:      "admin", // Admin trying to change their own role
					CreatedAt: time.Now(),
					UpdatedAt: time.Now(),
				}, nil
			}
			return nil, models.ErrNotFound
		},
		UpdateUserFunc: func(id string, user *models.User) (*models.User, error) {
			t.Fatal("UpdateUserFunc should not be called when admin tries to change own role")
			return nil, nil
		},
	}

	handler := handlers.NewUserHandler(mockService)

	// Admin tries to downgrade their own role to user
	reqBody := handlers.UpdateUserRequest{
		Name: "Admin User",
		Role: "user",
	}
	bodyBytes, _ := json.Marshal(reqBody)
	req := httptest.NewRequest("PUT", "/users/"+adminID, bytes.NewReader(bodyBytes))
	req.Header.Set("Content-Type", "application/json")

	// Add admin auth context
	claims := &models.TokenClaims{
		UserID: adminID,
		Email:  "admin@example.com",
		Type:   "access",
	}
	ctx := context.WithValue(req.Context(), auth.UserContextKey, claims)
	req = req.WithContext(ctx)

	// ✅ Add chi route context to set the {id} URL parameter
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("id", adminID)
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))

	w := httptest.NewRecorder()
	handler.UpdateUser(w, req)

	// Admin should get 403 Forbidden when trying to change their own role
	handlers.AssertErrorResponse(t, w, 403, "forbidden")
	assert.Contains(t, w.Body.String(), "own role", "Error message should mention cannot change own role")
}

// CRITICAL SECURITY TEST #1c: Privilege Escalation
// Verify that admins CAN change OTHER users' roles

func TestUpdateUser_AuthorizedRoleChange_AdminCanChangeOtherUserRole(t *testing.T) {
	adminID := "admin123"
	targetUserID := "user456"

	mockService := &handlers.MockUserService{
		GetUserByIDFunc: func(id string) (*models.User, error) {
			if id == adminID {
				return &models.User{
					ID:        adminID,
					Email:     "admin@example.com",
					Name:      "Admin User",
					Role:      "admin",
					CreatedAt: time.Now(),
					UpdatedAt: time.Now(),
				}, nil
			}
			if id == targetUserID {
				return &models.User{
					ID:        targetUserID,
					Email:     "user456@example.com",
					Name:      "Other User",
					Role:      "user",
					CreatedAt: time.Now(),
					UpdatedAt: time.Now(),
				}, nil
			}
			return nil, models.ErrNotFound
		},
		UpdateUserFunc: func(id string, user *models.User) (*models.User, error) {
			// Admin is changing another user's role - this is allowed
			if id == targetUserID && user.Role == "admin" {
				return &models.User{
					ID:        targetUserID,
					Email:     "user456@example.com",
					Name:      "Other User",
					Role:      "admin",
					CreatedAt: time.Now(),
					UpdatedAt: time.Now(),
				}, nil
			}
			return nil, models.ErrNotFound
		},
	}

	handler := handlers.NewUserHandler(mockService)

	// Admin promotes another user to admin
	reqBody := handlers.UpdateUserRequest{
		Name: "Other User",
		Role: "admin",
	}
	bodyBytes, _ := json.Marshal(reqBody)
	req := httptest.NewRequest("PUT", "/users/"+targetUserID, bytes.NewReader(bodyBytes))
	req.Header.Set("Content-Type", "application/json")

	// Add admin auth context
	claims := &models.TokenClaims{
		UserID: adminID,
		Email:  "admin@example.com",
		Type:   "access",
	}
	ctx := context.WithValue(req.Context(), auth.UserContextKey, claims)
	req = req.WithContext(ctx)

	// ✅ Add chi route context to set the {id} URL parameter
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("id", targetUserID)
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))

	w := httptest.NewRecorder()
	handler.UpdateUser(w, req)

	// This should succeed (200 OK), showing that admins CAN change other users' roles
	assert.NotEqual(t, 403, w.Code, "Admin should be allowed to change another user's role")
}
