package handlers

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"github.com/BradenHooton/kamino/internal/auth"
	"github.com/BradenHooton/kamino/internal/models"
	"github.com/go-chi/chi/v5"
)

// UserService defines the interface for user business logic
type UserService interface {
	GetUserByID(id string) (*models.User, error)
	ListUsers(limit, offset int) ([]*models.User, error)
	CreateUser(user *models.User, password string) (*models.User, error)
	UpdateUser(id string, user *models.User) (*models.User, error)
	DeleteUser(id string) error
}

// UserHandler handles user-related HTTP requests
type UserHandler struct {
	service UserService
}

// NewUserHandler creates a new UserHandler
func NewUserHandler(service UserService) *UserHandler {
	return &UserHandler{
		service: service,
	}
}

// Request/Response DTOs

// CreateUserRequest represents the request body for creating a user
type CreateUserRequest struct {
	Email    string `json:"email" validate:"required,email"`
	Name     string `json:"name" validate:"required,min=1"`
	Password string `json:"password" validate:"required"`
	Role     string `json:"role" validate:"omitempty,oneof=user admin"`
}

// UpdateUserRequest represents the request body for updating a user
type UpdateUserRequest struct {
	Name string `json:"name" validate:"omitempty,min=1"`
	Role string `json:"role" validate:"omitempty,oneof=user admin"`
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

// ListUsersResponse represents a list of users
type ListUsersResponse struct {
	Users []*UserResponse `json:"users"`
	Total int             `json:"total"`
}

// userModelToResponse converts a user model to a response DTO
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

// RegisterRoutes registers all user routes with the chi router
func (h *UserHandler) RegisterRoutes(router chi.Router) {
	router.Route("/users", func(r chi.Router) {
		r.Post("/", h.CreateUser)       // POST /users
		r.Get("/", h.ListUsers)         // GET /users
		r.Get("/{id}", h.GetUser)       // GET /users/{id}
		r.Put("/{id}", h.UpdateUser)    // PUT /users/{id}
		r.Delete("/{id}", h.DeleteUser) // DELETE /users/{id}
	})
}

// GetUser retrieves a user by ID
//
// @Summary Get user by ID
// @Param id path string true "User ID"
// @Produce json
// @Success 200 {object} UserResponse
// @Failure 403 {object} ErrorResponse
// @Failure 404 {object} ErrorResponse
// @Failure 500 {object} ErrorResponse
// @Router /users/{id} [get]
func (h *UserHandler) GetUser(w http.ResponseWriter, r *http.Request) {
	userID := chi.URLParam(r, "id")
	if userID == "" {
		http.Error(w, "User ID is required", http.StatusBadRequest)
		return
	}

	// Check resource-level authorization
	if err := h.checkUserAccess(r, userID); err != nil {
		http.Error(w, "Forbidden: you cannot access this resource", http.StatusForbidden)
		return
	}

	user, err := h.service.GetUserByID(userID)
	if err != nil {
		if errors.Is(err, models.ErrNotFound) {
			http.Error(w, "User not found", http.StatusNotFound)
			return
		}
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(userModelToResponse(user))
}

// ListUsers retrieves a list of users with pagination
//
// @Summary List users
// @Param limit query int false "Limit (default 10)" default(10)
// @Param offset query int false "Offset (default 0)" default(0)
// @Produce json
// @Success 200 {object} ListUsersResponse
// @Failure 400 {object} ErrorResponse
// @Failure 500 {object} ErrorResponse
// @Router /users [get]
func (h *UserHandler) ListUsers(w http.ResponseWriter, r *http.Request) {
	limit := 10
	offset := 0

	// Parse query parameters
	if l := r.URL.Query().Get("limit"); l != "" {
		_, err := parseIntParam(l, &limit, 1, 100)
		if err != nil {
			http.Error(w, "Invalid limit parameter", http.StatusBadRequest)
			return
		}
	}

	if o := r.URL.Query().Get("offset"); o != "" {
		_, err := parseIntParam(o, &offset, 0, 10000)
		if err != nil {
			http.Error(w, "Invalid offset parameter", http.StatusBadRequest)
			return
		}
	}

	users, err := h.service.ListUsers(limit, offset)
	if err != nil {
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	response := &ListUsersResponse{
		Users: make([]*UserResponse, len(users)),
		Total: len(users),
	}

	for i, user := range users {
		response.Users[i] = userModelToResponse(user)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// CreateUser creates a new user
//
// @Summary Create a new user
// @Accept json
// @Param request body CreateUserRequest true "Create user request"
// @Produce json
// @Success 201 {object} UserResponse
// @Failure 400 {object} ErrorResponse
// @Failure 409 {object} ErrorResponse
// @Failure 500 {object} ErrorResponse
// @Router /users [post]
func (h *UserHandler) CreateUser(w http.ResponseWriter, r *http.Request) {
	var req CreateUserRequest

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	// Validate request
	if err := ValidateRequest(req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// Normalize email
	req.Email = strings.ToLower(strings.TrimSpace(req.Email))

	// Create user model
	user := &models.User{
		Email: req.Email,
		Name:  strings.TrimSpace(req.Name),
		Role:  req.Role,
	}

	if user.Role == "" {
		user.Role = "user" // Default role
	}

	// Create user in service (pass password)
	createdUser, err := h.service.CreateUser(user, req.Password)
	if err != nil {
		if errors.Is(err, models.ErrConflict) {
			http.Error(w, "User already exists", http.StatusConflict)
			return
		}
		// Check if it's a password validation error
		if strings.Contains(err.Error(), "password requirements not met") {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(userModelToResponse(createdUser))
}

// UpdateUser updates an existing user
//
// @Summary Update a user
// @Param id path string true "User ID"
// @Accept json
// @Param request body UpdateUserRequest true "Update user request"
// @Produce json
// @Success 200 {object} UserResponse
// @Failure 400 {object} ErrorResponse
// @Failure 403 {object} ErrorResponse
// @Failure 404 {object} ErrorResponse
// @Failure 500 {object} ErrorResponse
// @Router /users/{id} [put]
func (h *UserHandler) UpdateUser(w http.ResponseWriter, r *http.Request) {
	userID := chi.URLParam(r, "id")
	if userID == "" {
		http.Error(w, "User ID is required", http.StatusBadRequest)
		return
	}

	// Check resource-level authorization
	if err := h.checkUserAccess(r, userID); err != nil {
		http.Error(w, "Forbidden: you cannot access this resource", http.StatusForbidden)
		return
	}

	var req UpdateUserRequest

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	// Validate request
	if err := ValidateRequest(req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// Create update model with only provided fields
	user := &models.User{
		ID: userID,
	}

	if req.Name != "" {
		user.Name = strings.TrimSpace(req.Name)
	}

	if req.Role != "" {
		user.Role = req.Role
	}

	// Update user in service
	updatedUser, err := h.service.UpdateUser(userID, user)
	if err != nil {
		if errors.Is(err, models.ErrNotFound) {
			http.Error(w, "User not found", http.StatusNotFound)
			return
		}
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(userModelToResponse(updatedUser))
}

// DeleteUser deletes a user
//
// @Summary Delete a user
// @Param id path string true "User ID"
// @Success 204
// @Failure 404 {object} ErrorResponse
// @Failure 500 {object} ErrorResponse
// @Router /users/{id} [delete]
func (h *UserHandler) DeleteUser(w http.ResponseWriter, r *http.Request) {
	userID := chi.URLParam(r, "id")
	if userID == "" {
		http.Error(w, "User ID is required", http.StatusBadRequest)
		return
	}

	err := h.service.DeleteUser(userID)
	if err != nil {
		if errors.Is(err, models.ErrNotFound) {
			http.Error(w, "User not found", http.StatusNotFound)
			return
		}
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// Helper functions

// checkUserAccess verifies that the authenticated user can access the requested resource
// Allows access if: user is accessing their own data OR user is admin
func (h *UserHandler) checkUserAccess(r *http.Request, requestedUserID string) error {
	claims := auth.GetUserFromContext(r)
	if claims == nil {
		return errors.New("user not found in context")
	}

	// User can access their own data
	if claims.UserID == requestedUserID {
		return nil
	}

	// Admin can access any user
	user, err := h.service.GetUserByID(claims.UserID)
	if err != nil {
		return err
	}

	if user.Role == "admin" {
		return nil
	}

	return errors.New("insufficient permissions")
}

// parseIntParam parses and validates an integer parameter
func parseIntParam(value string, dest *int, min, max int) (int, error) {
	n := 0
	_, err := scanInt(value, &n)
	if err != nil {
		return 0, err
	}

	if n < min || n > max {
		return 0, errors.New("parameter out of range")
	}

	*dest = n
	return n, nil
}

// scanInt is a helper to parse an integer from a string
func scanInt(s string, dest *int) (int, error) {
	err := json.Unmarshal([]byte(s), dest)
	return *dest, err
}
