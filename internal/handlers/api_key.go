package handlers

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/BradenHooton/kamino/internal/auth"
	"github.com/BradenHooton/kamino/internal/models"
	"github.com/BradenHooton/kamino/internal/services"
	pkghttp "github.com/BradenHooton/kamino/pkg/http"
	"github.com/go-chi/chi/v5"
)

// APIKeyServiceInterface defines the interface for API key operations
type APIKeyServiceInterface interface {
	CreateAPIKey(ctx context.Context, userID string, name string, scopes []string, expiresAt *time.Time) (*models.GeneratedAPIKey, error)
	ValidateAPIKey(ctx context.Context, plainKey string) (*models.APIKey, error)
	ListUserKeys(ctx context.Context, userID string, limit, offset int) ([]*models.APIKey, error)
	RevokeAPIKey(ctx context.Context, userID string, keyID string) error
	GetAPIKey(ctx context.Context, userID string, keyID string) (*models.APIKey, error)
}

// APIKeyHandler handles API key HTTP requests
type APIKeyHandler struct {
	service      APIKeyServiceInterface
	userService  UserService
	auditService *services.AuditService
}

// NewAPIKeyHandler creates a new APIKeyHandler
func NewAPIKeyHandler(service APIKeyServiceInterface, userService UserService, auditService *services.AuditService) *APIKeyHandler {
	return &APIKeyHandler{
		service:      service,
		userService:  userService,
		auditService: auditService,
	}
}

// Request DTOs

// CreateAPIKeyRequest represents the request to create an API key
type CreateAPIKeyRequest struct {
	Name      string    `json:"name" validate:"required,min=1,max=255"`
	Scopes    []string  `json:"scopes" validate:"required,min=1,dive,required"`
	ExpiresAt *string   `json:"expires_at,omitempty" validate:"omitempty,datetime=2006-01-02T15:04:05Z07:00"` // RFC3339 format
}

// ListAPIKeysResponse represents the response for listing API keys
type ListAPIKeysResponse struct {
	Keys  []*APIKeyDTO `json:"keys"`
	Total int          `json:"total"`
	Limit int          `json:"limit"`
	Offset int          `json:"offset"`
}

// APIKeyDTO is the response DTO for API keys (never includes plaintext)
type APIKeyDTO struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	KeyPrefix string    `json:"key_prefix"`
	Scopes    []string  `json:"scopes"`
	LastUsedAt *time.Time `json:"last_used_at,omitempty"`
	ExpiresAt *time.Time `json:"expires_at,omitempty"`
	RevokedAt *time.Time `json:"revoked_at,omitempty"`
	CreatedAt time.Time  `json:"created_at"`
	UpdatedAt time.Time  `json:"updated_at"`
}

// RevokeAPIKeyRequest represents the request to revoke an API key
type RevokeAPIKeyRequest struct {
	Reason *string `json:"reason,omitempty"` // Optional reason for revocation
}

// Handlers

// CreateAPIKey POST /api-keys
func (h *APIKeyHandler) CreateAPIKey(w http.ResponseWriter, r *http.Request) {
	claims := auth.GetUserFromContext(r)
	if claims == nil {
		pkghttp.WriteUnauthorized(w, "unauthorized")
		return
	}

	var req CreateAPIKeyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		pkghttp.WriteBadRequest(w, "invalid request body")
		return
	}

	// Validate inputs
	if req.Name == "" {
		pkghttp.WriteBadRequest(w, "name is required")
		return
	}
	if len(req.Scopes) == 0 {
		pkghttp.WriteBadRequest(w, "at least one scope is required")
		return
	}

	// AUTHORIZATION: Check if user's role allows requested scopes
	// Prevent privilege escalation: regular users cannot request admin-only scopes
	user, err := h.userService.GetUserByID(claims.UserID)
	if err != nil {
		if errors.Is(err, models.ErrNotFound) {
			pkghttp.WriteUnauthorized(w, "user not found")
			return
		}
		pkghttp.WriteInternalError(w, "failed to fetch user")
		return
	}

	// Validate each scope against user's role
	for _, scope := range req.Scopes {
		if !models.CanUserRequestScope(user.Role, scope) {
			pkghttp.WriteForbidden(w, "insufficient permissions to request scope: "+scope)
			return
		}
	}

	// Parse expiration time if provided
	var expiresAt *time.Time
	if req.ExpiresAt != nil {
		t, err := time.Parse(time.RFC3339, *req.ExpiresAt)
		if err != nil {
			pkghttp.WriteBadRequest(w, "invalid expires_at format (use RFC3339)")
			return
		}
		expiresAt = &t
	}

	// Create API key
	generated, err := h.service.CreateAPIKey(r.Context(), claims.UserID, req.Name, req.Scopes, expiresAt)
	if err != nil {
		if err == models.ErrBadRequest {
			pkghttp.WriteBadRequest(w, "invalid request")
			return
		}
		pkghttp.WriteInternalError(w, "failed to create api key")
		return
	}

	// Return plaintext key ONLY once
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"key":     generated.PlainKey,
		"message": "Save this API key - it will not be shown again",
		"api_key": toAPIKeyDTO(generated.APIKey),
	})
}

// ListAPIKeys GET /api-keys
func (h *APIKeyHandler) ListAPIKeys(w http.ResponseWriter, r *http.Request) {
	claims := auth.GetUserFromContext(r)
	if claims == nil {
		pkghttp.WriteUnauthorized(w, "unauthorized")
		return
	}

	// Parse query parameters
	limit := 20
	offset := 0

	if l := r.URL.Query().Get("limit"); l != "" {
		_, err := parseIntParam(l, &limit, 1, 100)
		if err != nil {
			pkghttp.WriteBadRequest(w, "Invalid limit parameter")
			return
		}
	}

	if o := r.URL.Query().Get("offset"); o != "" {
		_, err := parseIntParam(o, &offset, 0, 10000)
		if err != nil {
			pkghttp.WriteBadRequest(w, "Invalid offset parameter")
			return
		}
	}

	// List keys
	keys, err := h.service.ListUserKeys(r.Context(), claims.UserID, limit, offset)
	if err != nil {
		pkghttp.WriteInternalError(w, "failed to list api keys")
		return
	}

	// Convert to DTOs
	keyDTOs := make([]*APIKeyDTO, len(keys))
	for i, key := range keys {
		keyDTOs[i] = toAPIKeyDTO(key)
	}

	// Return response
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(ListAPIKeysResponse{
		Keys:   keyDTOs,
		Total:  len(keyDTOs),
		Limit:  limit,
		Offset: offset,
	})
}

// GetAPIKey GET /api-keys/{id}
func (h *APIKeyHandler) GetAPIKey(w http.ResponseWriter, r *http.Request) {
	claims := auth.GetUserFromContext(r)
	if claims == nil {
		pkghttp.WriteUnauthorized(w, "unauthorized")
		return
	}

	keyID := chi.URLParam(r, "id")
	if keyID == "" {
		pkghttp.WriteBadRequest(w, "invalid key id")
		return
	}

	// Get key
	key, err := h.service.GetAPIKey(r.Context(), claims.UserID, keyID)
	if err != nil {
		if err == models.ErrNotFound {
			pkghttp.WriteNotFound(w, "api key not found")
			return
		}
		if err == models.ErrForbidden {
			pkghttp.WriteForbidden(w, "cannot access this api key")
			return
		}
		pkghttp.WriteInternalError(w, "failed to get api key")
		return
	}

	// Return key
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(toAPIKeyDTO(key))
}

// RevokeAPIKey DELETE /api-keys/{id}
func (h *APIKeyHandler) RevokeAPIKey(w http.ResponseWriter, r *http.Request) {
	claims := auth.GetUserFromContext(r)
	if claims == nil {
		pkghttp.WriteUnauthorized(w, "unauthorized")
		return
	}

	keyID := chi.URLParam(r, "id")
	if keyID == "" {
		pkghttp.WriteBadRequest(w, "invalid key id")
		return
	}

	// Parse optional request body
	var req RevokeAPIKeyRequest
	if r.ContentLength > 0 {
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			pkghttp.WriteBadRequest(w, "invalid request body")
			return
		}
	}

	// Revoke key
	if err := h.service.RevokeAPIKey(r.Context(), claims.UserID, keyID); err != nil {
		if err == models.ErrNotFound {
			pkghttp.WriteNotFound(w, "api key not found")
			return
		}
		if err == models.ErrForbidden {
			pkghttp.WriteForbidden(w, "cannot revoke this api key")
			return
		}
		if err == models.ErrBadRequest {
			pkghttp.WriteBadRequest(w, "api key already revoked")
			return
		}
		pkghttp.WriteInternalError(w, "failed to revoke api key")
		return
	}

	// Return success
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"message": "api key revoked",
	})
}

// Helpers

// toAPIKeyDTO converts an APIKey model to a response DTO (never includes plaintext)
func toAPIKeyDTO(key *models.APIKey) *APIKeyDTO {
	if key == nil {
		return nil
	}
	return &APIKeyDTO{
		ID:         key.ID,
		Name:       key.Name,
		KeyPrefix:  key.KeyPrefix,
		Scopes:     key.Scopes,
		LastUsedAt: key.LastUsedAt,
		ExpiresAt:  key.ExpiresAt,
		RevokedAt:  key.RevokedAt,
		CreatedAt:  key.CreatedAt,
		UpdatedAt:  key.UpdatedAt,
	}
}
