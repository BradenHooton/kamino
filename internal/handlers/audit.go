package handlers

import (
	"encoding/json"
	"net/http"
	"strconv"

	"github.com/BradenHooton/kamino/internal/auth"
	"github.com/BradenHooton/kamino/internal/models"
	"github.com/BradenHooton/kamino/internal/services"
	pkghttp "github.com/BradenHooton/kamino/pkg/http"
	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
)

// AuditHandler handles audit log HTTP requests
type AuditHandler struct {
	auditService services.AuditService
}

// NewAuditHandler creates a new AuditHandler
func NewAuditHandler(auditService *services.AuditService) *AuditHandler {
	return &AuditHandler{
		auditService: *auditService,
	}
}

// AuditLogResponse represents an audit log entry in HTTP response
type AuditLogResponse struct {
	ID            string                 `json:"id"`
	EventType     string                 `json:"event_type"`
	ActorID       *string                `json:"actor_id,omitempty"`
	TargetID      *string                `json:"target_id,omitempty"`
	ResourceType  *string                `json:"resource_type,omitempty"`
	ResourceID    *string                `json:"resource_id,omitempty"`
	Action        string                 `json:"action"`
	Success       bool                   `json:"success"`
	FailureReason *string                `json:"failure_reason,omitempty"`
	IPAddress     *string                `json:"ip_address,omitempty"`
	UserAgent     *string                `json:"user_agent,omitempty"`
	Metadata      map[string]interface{} `json:"metadata,omitempty"`
	CreatedAt     string                 `json:"created_at"`
}

// GetUserAuditTrail retrieves the audit trail for a specific user (admin only)
func (h *AuditHandler) GetUserAuditTrail(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// Get authenticated user from context
	claims := auth.GetUserFromContext(r)
	if claims == nil {
		pkghttp.WriteError(w, http.StatusUnauthorized, models.ErrUnauthorized)
		return
	}

	// Check if user is admin
	if claims.Role != "admin" {
		pkghttp.WriteError(w, http.StatusForbidden, models.ErrForbidden)
		return
	}

	// Get target user ID from URL parameter
	userIDStr := chi.URLParam(r, "id")
	targetUserID, err := uuid.Parse(userIDStr)
	if err != nil {
		pkghttp.WriteError(w, http.StatusBadRequest, models.ErrBadRequest, "invalid user id")
		return
	}

	// Get pagination parameters
	limitStr := r.URL.Query().Get("limit")
	offsetStr := r.URL.Query().Get("offset")

	limit := 50
	offset := 0

	if limitStr != "" {
		if l, err := strconv.Atoi(limitStr); err == nil && l > 0 && l <= 100 {
			limit = l
		}
	}

	if offsetStr != "" {
		if o, err := strconv.Atoi(offsetStr); err == nil && o >= 0 {
			offset = o
		}
	}

	// Get audit logs
	logs, err := h.auditService.GetUserAuditTrail(ctx, targetUserID, limit, offset)
	if err != nil {
		pkghttp.WriteError(w, http.StatusInternalServerError, models.ErrInternalServer)
		return
	}

	// Get total count
	count, err := h.auditService.GetCountForUser(ctx, targetUserID)
	if err != nil {
		pkghttp.WriteError(w, http.StatusInternalServerError, models.ErrInternalServer)
		return
	}

	// Convert to response format
	response := make([]*AuditLogResponse, len(logs))
	for i, log := range logs {
		response[i] = auditLogToResponse(log)
	}

	// Write response
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Total-Count", strconv.FormatInt(count, 10))
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"logs":   response,
		"total":  count,
		"limit":  limit,
		"offset": offset,
	})
}

// auditLogToResponse converts an audit log model to a response DTO
func auditLogToResponse(log *models.AuditLog) *AuditLogResponse {
	resp := &AuditLogResponse{
		ID:            log.ID.String(),
		EventType:     log.EventType,
		Action:        log.Action,
		Success:       log.Success,
		CreatedAt:     log.CreatedAt.Format("2006-01-02T15:04:05Z07:00"),
		Metadata:      log.Metadata,
	}

	if log.ActorID != nil {
		actorStr := log.ActorID.String()
		resp.ActorID = &actorStr
	}

	if log.TargetID != nil {
		targetStr := log.TargetID.String()
		resp.TargetID = &targetStr
	}

	if log.ResourceType != nil {
		resp.ResourceType = log.ResourceType
	}

	if log.ResourceID != nil {
		resp.ResourceID = log.ResourceID
	}

	if log.FailureReason != nil {
		resp.FailureReason = log.FailureReason
	}

	if log.IPAddress != nil {
		resp.IPAddress = log.IPAddress
	}

	if log.UserAgent != nil {
		resp.UserAgent = log.UserAgent
	}

	return resp
}
