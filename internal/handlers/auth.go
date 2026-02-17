package handlers

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"github.com/BradenHooton/kamino/internal/auth"
	"github.com/BradenHooton/kamino/internal/models"
	"github.com/BradenHooton/kamino/internal/services"
)

// AuthServiceInterface defines the interface for auth business logic
type AuthServiceInterface interface {
	Login(ctx context.Context, email, password string) (*services.AuthResponse, error)
	Register(ctx context.Context, email, password, name string) (*services.AuthResponse, error)
	RefreshToken(ctx context.Context, refreshToken string) (*services.AuthResponse, error)
	Logout(ctx context.Context, accessToken string) error
	LogoutAll(ctx context.Context, userID string) error
}

// AuthHandler handles authentication-related HTTP requests
type AuthHandler struct {
	service AuthServiceInterface
}

// NewAuthHandler creates a new AuthHandler
func NewAuthHandler(service AuthServiceInterface) *AuthHandler {
	return &AuthHandler{
		service: service,
	}
}

// Request DTOs

// LoginRequest represents the request body for login
type LoginRequest struct {
	Email    string `json:"email" validate:"required,email"`
	Password string `json:"password" validate:"required"`
}

// RegisterRequest represents the request body for registration
type RegisterRequest struct {
	Email    string `json:"email" validate:"required,email"`
	Password string `json:"password" validate:"required"`
	Name     string `json:"name" validate:"required,min=1"`
}

// RefreshTokenRequest represents the request body for token refresh
type RefreshTokenRequest struct {
	RefreshToken string `json:"refresh_token" validate:"required"`
}

// Login handles user login
// @Summary User login
// @Accept json
// @Param request body LoginRequest true "Login request"
// @Produce json
// @Success 200 {object} services.AuthResponse
// @Failure 400 {object} ErrorResponse
// @Failure 401 {object} ErrorResponse
// @Failure 500 {object} ErrorResponse
// @Router /auth/login [post]
func (h *AuthHandler) Login(w http.ResponseWriter, r *http.Request) {
	var req LoginRequest

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

	// Authenticate user
	authResp, err := h.service.Login(r.Context(), req.Email, req.Password)
	if err != nil {
		switch {
		case errors.Is(err, models.ErrUnauthorized):
			http.Error(w, "Authentication failed", http.StatusUnauthorized)
		case errors.Is(err, models.ErrAccountDisabled),
			errors.Is(err, models.ErrAccountSuspended),
			errors.Is(err, models.ErrAccountLocked),
			errors.Is(err, models.ErrEmailNotVerified):
			// Return generic error for all account status issues to prevent user enumeration
			http.Error(w, "Authentication failed", http.StatusUnauthorized)
		default:
			http.Error(w, "Internal server error", http.StatusInternalServerError)
		}
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(authResp)
}

// Register handles user registration
// @Summary User registration
// @Accept json
// @Param request body RegisterRequest true "Register request"
// @Produce json
// @Success 201 {object} services.AuthResponse
// @Failure 400 {object} ErrorResponse
// @Failure 409 {object} ErrorResponse
// @Failure 500 {object} ErrorResponse
// @Router /auth/register [post]
func (h *AuthHandler) Register(w http.ResponseWriter, r *http.Request) {
	var req RegisterRequest

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	// Validate request
	if err := ValidateRequest(req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// Normalize email and name
	req.Email = strings.ToLower(strings.TrimSpace(req.Email))
	req.Name = strings.TrimSpace(req.Name)

	// Create user
	authResp, err := h.service.Register(r.Context(), req.Email, req.Password, req.Name)
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
	json.NewEncoder(w).Encode(authResp)
}

// RefreshToken handles token refresh
// @Summary Refresh access token
// @Accept json
// @Param request body RefreshTokenRequest true "Refresh token request"
// @Produce json
// @Success 200 {object} services.AuthResponse
// @Failure 400 {object} ErrorResponse
// @Failure 401 {object} ErrorResponse
// @Failure 500 {object} ErrorResponse
// @Router /auth/refresh [post]
func (h *AuthHandler) RefreshToken(w http.ResponseWriter, r *http.Request) {
	var req RefreshTokenRequest

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	// Validate request
	if err := ValidateRequest(req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// Refresh tokens
	authResp, err := h.service.RefreshToken(r.Context(), req.RefreshToken)
	if err != nil {
		switch {
		case errors.Is(err, models.ErrUnauthorized):
			http.Error(w, "Authentication failed", http.StatusUnauthorized)
		case errors.Is(err, models.ErrAccountDisabled),
			errors.Is(err, models.ErrAccountSuspended),
			errors.Is(err, models.ErrAccountLocked):
			// Return generic error for all account status issues to prevent user enumeration
			http.Error(w, "Authentication failed", http.StatusUnauthorized)
		default:
			http.Error(w, "Internal server error", http.StatusInternalServerError)
		}
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(authResp)
}

// Logout handles user logout by revoking the access token
// @Summary User logout
// @Accept json
// @Security BearerAuth
// @Produce json
// @Success 204
// @Failure 400 {object} ErrorResponse
// @Failure 401 {object} ErrorResponse
// @Failure 500 {object} ErrorResponse
// @Router /auth/logout [post]
func (h *AuthHandler) Logout(w http.ResponseWriter, r *http.Request) {
	// Extract token from Authorization header
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		http.Error(w, "missing authorization header", http.StatusBadRequest)
		return
	}

	parts := strings.SplitN(authHeader, " ", 2)
	if len(parts) != 2 || parts[0] != "Bearer" {
		http.Error(w, "invalid authorization header format", http.StatusBadRequest)
		return
	}

	accessToken := parts[1]

	// Revoke the token
	err := h.service.Logout(r.Context(), accessToken)
	if err != nil {
		if errors.Is(err, models.ErrUnauthorized) {
			http.Error(w, "Invalid token", http.StatusUnauthorized)
			return
		}
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusNoContent) // 204 No Content
}

// LogoutAll handles logout from all devices
// @Summary Logout from all devices
// @Accept json
// @Security BearerAuth
// @Produce json
// @Success 204
// @Failure 401 {object} ErrorResponse
// @Failure 500 {object} ErrorResponse
// @Router /auth/logout-all [post]
func (h *AuthHandler) LogoutAll(w http.ResponseWriter, r *http.Request) {
	// Get user from context (set by AuthMiddleware)
	claims := auth.GetUserFromContext(r)
	if claims == nil {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	// Logout from all devices
	err := h.service.LogoutAll(r.Context(), claims.UserID)
	if err != nil {
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusNoContent) // 204 No Content
}
