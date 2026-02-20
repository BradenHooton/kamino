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
	pkghttp "github.com/BradenHooton/kamino/pkg/http"
)

// AuthServiceInterface defines the interface for auth business logic
type AuthServiceInterface interface {
	Login(ctx context.Context, email, password, ipAddress, userAgent string) (*services.AuthResponse, error)
	Register(ctx context.Context, email, password, name string) (*services.AuthResponse, error)
	RefreshToken(ctx context.Context, refreshToken string) (*services.AuthResponse, error)
	Logout(ctx context.Context, accessToken string) error
	LogoutAll(ctx context.Context, userID string) error
}

// EmailVerificationServiceInterface defines the interface for email verification
type EmailVerificationServiceInterface interface {
	SendVerificationEmail(ctx context.Context, userID, email string) error
	VerifyEmail(ctx context.Context, plainToken string) (string, error)
	ResendVerification(ctx context.Context, email string) error
	GetStatus(ctx context.Context, userID string) (bool, error)
}

// AuthHandler handles authentication-related HTTP requests
type AuthHandler struct {
	service                      AuthServiceInterface
	emailVerificationService     EmailVerificationServiceInterface
	ipConfig                     *pkghttp.IPConfig
}

// NewAuthHandler creates a new AuthHandler
func NewAuthHandler(service AuthServiceInterface, ipConfig *pkghttp.IPConfig) *AuthHandler {
	return &AuthHandler{
		service:  service,
		ipConfig: ipConfig,
	}
}

// NewAuthHandlerWithEmailVerification creates a new AuthHandler with email verification support
func NewAuthHandlerWithEmailVerification(service AuthServiceInterface, emailVerificationService EmailVerificationServiceInterface, ipConfig *pkghttp.IPConfig) *AuthHandler {
	return &AuthHandler{
		service:                  service,
		emailVerificationService: emailVerificationService,
		ipConfig:                 ipConfig,
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

// VerifyEmailRequest represents the request body for email verification
type VerifyEmailRequest struct {
	Token string `json:"token" validate:"required"`
}

// ResendVerificationRequest represents the request body for resending verification email
type ResendVerificationRequest struct {
	Email string `json:"email" validate:"required,email"`
}

// VerificationStatusResponse represents the response for verification status
type VerificationStatusResponse struct {
	EmailVerified       bool `json:"email_verified"`
	VerificationRequired bool `json:"verification_required"`
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
		pkghttp.WriteBadRequest(w, "Invalid request body")
		return
	}

	// Validate request
	if err := ValidateRequest(req); err != nil {
		pkghttp.WriteBadRequest(w, err.Error())
		return
	}

	// Normalize email
	req.Email = strings.ToLower(strings.TrimSpace(req.Email))

	// Extract IP address and User-Agent for rate limiting
	ipAddress := pkghttp.ExtractClientIP(r, h.ipConfig)
	userAgent := r.Header.Get("User-Agent")

	// Authenticate user
	authResp, err := h.service.Login(r.Context(), req.Email, req.Password, ipAddress, userAgent)
	if err != nil {
		switch {
		case errors.Is(err, models.ErrUnauthorized):
			pkghttp.WriteUnauthorized(w, "Authentication failed")
		case errors.Is(err, models.ErrRateLimitExceeded),
			errors.Is(err, models.ErrAccountLockedBySystem):
			pkghttp.WriteTooManyRequests(w, "Too many failed login attempts. Please try again later.")
		case errors.Is(err, models.ErrAccountDisabled),
			errors.Is(err, models.ErrAccountSuspended),
			errors.Is(err, models.ErrAccountLocked),
			errors.Is(err, models.ErrEmailNotVerified):
			// Return generic error for all account status issues to prevent user enumeration
			pkghttp.WriteUnauthorized(w, "Authentication failed")
		default:
			pkghttp.WriteInternalError(w, "Internal server error")
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
		pkghttp.WriteBadRequest(w, "Invalid request body")
		return
	}

	// Validate request
	if err := ValidateRequest(req); err != nil {
		pkghttp.WriteBadRequest(w, err.Error())
		return
	}

	// Normalize email and name
	req.Email = strings.ToLower(strings.TrimSpace(req.Email))
	req.Name = strings.TrimSpace(req.Name)

	// Create user
	_, err := h.service.Register(r.Context(), req.Email, req.Password, req.Name)
	if err != nil {
		// For any validation/conflict errors, return generic success message
		// This prevents user enumeration attacks (e.g., "user already exists", specific password requirements)
		// The user receives a "check your email" message either way
		if errors.Is(err, models.ErrConflict) || strings.Contains(err.Error(), "invalid password") {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusAccepted)
			json.NewEncoder(w).Encode(map[string]string{
				"message": "Registration received. If the email is not already registered, you will receive a confirmation email.",
			})
			return
		}

		// All other errors
		pkghttp.WriteInternalError(w, "Internal server error")
		return
	}

	// Successful new registration - return identical response
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusAccepted)
	json.NewEncoder(w).Encode(map[string]string{
		"message": "Registration received. If the email is not already registered, you will receive a confirmation email.",
	})
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
		pkghttp.WriteBadRequest(w, "Invalid request body")
		return
	}

	// Validate request
	if err := ValidateRequest(req); err != nil {
		pkghttp.WriteBadRequest(w, err.Error())
		return
	}

	// Refresh tokens
	authResp, err := h.service.RefreshToken(r.Context(), req.RefreshToken)
	if err != nil {
		switch {
		case errors.Is(err, models.ErrUnauthorized):
			pkghttp.WriteUnauthorized(w, "Authentication failed")
		case errors.Is(err, models.ErrAccountDisabled),
			errors.Is(err, models.ErrAccountSuspended),
			errors.Is(err, models.ErrAccountLocked),
			errors.Is(err, models.ErrEmailNotVerified):
			// Return generic error for all account status issues to prevent user enumeration
			pkghttp.WriteUnauthorized(w, "Authentication failed")
		default:
			pkghttp.WriteInternalError(w, "Internal server error")
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
// @Failure 401 {object} ErrorResponse
// @Failure 500 {object} ErrorResponse
// @Router /auth/logout [post]
func (h *AuthHandler) Logout(w http.ResponseWriter, r *http.Request) {
	// Get user claims from context (added by AuthMiddleware)
	claims := auth.GetUserFromContext(r)
	if claims == nil {
		pkghttp.WriteUnauthorized(w, "unauthorized")
		return
	}

	// Validate token type is "access" (defense-in-depth check)
	if claims.Type != "access" {
		pkghttp.WriteUnauthorized(w, "unauthorized")
		return
	}

	// Get raw token for revocation
	accessToken := auth.GetTokenFromContext(r)
	if accessToken == "" {
		pkghttp.WriteUnauthorized(w, "unauthorized")
		return
	}

	// Revoke the token
	err := h.service.Logout(r.Context(), accessToken)
	if err != nil {
		if errors.Is(err, models.ErrUnauthorized) {
			pkghttp.WriteUnauthorized(w, "Invalid token")
			return
		}
		pkghttp.WriteInternalError(w, "Internal server error")
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
		pkghttp.WriteUnauthorized(w, "unauthorized")
		return
	}

	// Logout from all devices
	err := h.service.LogoutAll(r.Context(), claims.UserID)
	if err != nil {
		pkghttp.WriteInternalError(w, "Internal server error")
		return
	}

	w.WriteHeader(http.StatusNoContent) // 204 No Content
}

// VerifyEmail handles email verification with a token
// @Summary Verify email address
// @Accept json
// @Param request body VerifyEmailRequest true "Verify email request"
// @Produce json
// @Success 200 {object} services.AuthResponse
// @Failure 400 {object} ErrorResponse
// @Failure 401 {object} ErrorResponse
// @Failure 500 {object} ErrorResponse
// @Router /auth/verify-email [post]
func (h *AuthHandler) VerifyEmail(w http.ResponseWriter, r *http.Request) {
	if h.emailVerificationService == nil {
		pkghttp.WriteInternalError(w, "Internal server error")
		return
	}

	var req VerifyEmailRequest

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		pkghttp.WriteBadRequest(w, "Invalid request body")
		return
	}

	// Validate request
	if err := ValidateRequest(req); err != nil {
		pkghttp.WriteBadRequest(w, err.Error())
		return
	}

	// Verify email with token
	userID, err := h.emailVerificationService.VerifyEmail(r.Context(), req.Token)
	if err != nil {
		if errors.Is(err, models.ErrUnauthorized) {
			pkghttp.WriteUnauthorized(w, "Invalid or expired verification token")
			return
		}
		pkghttp.WriteInternalError(w, "Internal server error")
		return
	}

	// Auto-login user after successful verification
	// For now, return success message - user logs in separately
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{
		"message": "Email verified successfully. Please log in.",
		"user_id": userID,
	})
}

// ResendVerification handles resending of verification email
// @Summary Resend verification email
// @Accept json
// @Param request body ResendVerificationRequest true "Resend verification request"
// @Produce json
// @Success 202
// @Failure 400 {object} ErrorResponse
// @Failure 500 {object} ErrorResponse
// @Router /auth/resend-verification [post]
func (h *AuthHandler) ResendVerification(w http.ResponseWriter, r *http.Request) {
	if h.emailVerificationService == nil {
		pkghttp.WriteInternalError(w, "Internal server error")
		return
	}

	var req ResendVerificationRequest

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		pkghttp.WriteBadRequest(w, "Invalid request body")
		return
	}

	// Validate request
	if err := ValidateRequest(req); err != nil {
		pkghttp.WriteBadRequest(w, err.Error())
		return
	}

	// Normalize email
	req.Email = strings.ToLower(strings.TrimSpace(req.Email))

	// Resend verification email
	// Note: Always return 202 Accepted with generic message to prevent enumeration
	_ = h.emailVerificationService.ResendVerification(r.Context(), req.Email)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusAccepted)
	json.NewEncoder(w).Encode(map[string]string{
		"message": "If an account exists with this email, a verification email will be sent.",
	})
}

// VerificationStatus handles getting the email verification status for the current user
// @Summary Get email verification status
// @Security BearerAuth
// @Produce json
// @Success 200 {object} VerificationStatusResponse
// @Failure 401 {object} ErrorResponse
// @Failure 500 {object} ErrorResponse
// @Router /auth/verification-status [get]
func (h *AuthHandler) VerificationStatus(w http.ResponseWriter, r *http.Request) {
	if h.emailVerificationService == nil {
		pkghttp.WriteInternalError(w, "Internal server error")
		return
	}

	// Get user from context (set by AuthMiddleware)
	claims := auth.GetUserFromContext(r)
	if claims == nil {
		pkghttp.WriteUnauthorized(w, "unauthorized")
		return
	}

	// Get verification status
	isVerified, err := h.emailVerificationService.GetStatus(r.Context(), claims.UserID)
	if err != nil {
		pkghttp.WriteInternalError(w, "Internal server error")
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(VerificationStatusResponse{
		EmailVerified:       isVerified,
		VerificationRequired: !isVerified,
	})
}
