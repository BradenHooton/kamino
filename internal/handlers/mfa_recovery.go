package handlers

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"strconv"

	"github.com/BradenHooton/kamino/internal/auth"
	"github.com/BradenHooton/kamino/internal/models"
	"github.com/BradenHooton/kamino/internal/services"
	pkghttp "github.com/BradenHooton/kamino/pkg/http"
	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
)

// MFARecoveryHandler handles MFA recovery requests
type MFARecoveryHandler struct {
	service *services.MFARecoveryService
	logger  *slog.Logger
}

// NewMFARecoveryHandler creates a new MFA recovery handler
func NewMFARecoveryHandler(service *services.MFARecoveryService, logger *slog.Logger) *MFARecoveryHandler {
	return &MFARecoveryHandler{
		service: service,
		logger:  logger,
	}
}

// DTOs
type InitiateRecoveryRequest struct {
	UserID string `json:"user_id"`
	Reason string `json:"reason"`
}

type RecoveryResponse struct {
	ID               string  `json:"id"`
	UserID           string  `json:"user_id"`
	InitiatorAdminID string  `json:"initiator_admin_id"`
	ConfirmerAdminID *string `json:"confirmer_admin_id,omitempty"`
	Reason           string  `json:"reason"`
	Status           string  `json:"status"`
	CreatedAt        string  `json:"created_at"`
	ConfirmedAt      *string `json:"confirmed_at,omitempty"`
	ExpiresAt        string  `json:"expires_at"`
	ExecutedAt       *string `json:"executed_at,omitempty"`
}

// toRecoveryResponse converts a model to response DTO
func toRecoveryResponse(req *models.MFARecoveryRequest) RecoveryResponse {
	resp := RecoveryResponse{
		ID:               req.ID.String(),
		UserID:           req.UserID.String(),
		InitiatorAdminID: req.InitiatorAdminID.String(),
		Reason:           req.Reason,
		Status:           req.Status,
		CreatedAt:        req.CreatedAt.Format("2006-01-02T15:04:05Z"),
		ExpiresAt:        req.ExpiresAt.Format("2006-01-02T15:04:05Z"),
	}

	if req.ConfirmerAdminID != nil {
		confirmerID := req.ConfirmerAdminID.String()
		resp.ConfirmerAdminID = &confirmerID
	}

	if req.ConfirmedAt != nil {
		confirmedAt := req.ConfirmedAt.Format("2006-01-02T15:04:05Z")
		resp.ConfirmedAt = &confirmedAt
	}

	if req.ExecutedAt != nil {
		executedAt := req.ExecutedAt.Format("2006-01-02T15:04:05Z")
		resp.ExecutedAt = &executedAt
	}

	return resp
}

// InitiateRecovery initiates a new MFA recovery request
// POST /admin/mfa/recovery
func (h *MFARecoveryHandler) InitiateRecovery(w http.ResponseWriter, r *http.Request) {
	// Extract admin from context
	claims := auth.GetUserFromContext(r)
	if claims == nil {
		pkghttp.WriteUnauthorized(w, "authentication required")
		return
	}

	initiatorID, err := uuid.Parse(claims.UserID)
	if err != nil {
		h.logger.Error("invalid initiator ID", slog.Any("error", err))
		pkghttp.WriteInternalError(w, "invalid user ID")
		return
	}

	// Parse request body
	var req InitiateRecoveryRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		pkghttp.WriteBadRequest(w, "invalid request body")
		return
	}

	// Validate request
	if req.UserID == "" {
		pkghttp.WriteBadRequest(w, "user_id is required")
		return
	}

	if req.Reason == "" {
		pkghttp.WriteBadRequest(w, "reason is required")
		return
	}

	if len(req.Reason) < 10 {
		pkghttp.WriteBadRequest(w, "reason must be at least 10 characters")
		return
	}

	targetUserID, err := uuid.Parse(req.UserID)
	if err != nil {
		pkghttp.WriteBadRequest(w, "invalid user_id format")
		return
	}

	// Initiate recovery
	recoveryReq, err := h.service.InitiateRecovery(r.Context(), initiatorID, targetUserID, req.Reason)
	if err != nil {
		h.logger.Error("failed to initiate recovery",
			slog.Any("initiator_id", initiatorID),
			slog.Any("target_user_id", targetUserID),
			slog.Any("error", err))

		if err.Error() == "only admins can initiate recovery" {
			pkghttp.WriteForbidden(w, "insufficient privileges")
			return
		}

		if err.Error() == "user does not have MFA enabled" {
			pkghttp.WriteBadRequest(w, "user does not have MFA enabled")
			return
		}

		if err.Error() == "a recovery request already exists for this user" {
			pkghttp.WriteConflict(w, "a pending recovery request already exists for this user")
			return
		}

		pkghttp.WriteInternalError(w, "failed to initiate recovery")
		return
	}

	// Return recovery request
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(toRecoveryResponse(recoveryReq))
}

// ConfirmRecovery confirms a recovery request (second admin approval)
// POST /admin/mfa/recovery/{id}/confirm
func (h *MFARecoveryHandler) ConfirmRecovery(w http.ResponseWriter, r *http.Request) {
	// Extract admin from context
	claims := auth.GetUserFromContext(r)
	if claims == nil {
		pkghttp.WriteUnauthorized(w, "authentication required")
		return
	}

	confirmerID, err := uuid.Parse(claims.UserID)
	if err != nil {
		h.logger.Error("invalid confirmer ID", slog.Any("error", err))
		pkghttp.WriteInternalError(w, "invalid user ID")
		return
	}

	// Get request ID from URL
	requestIDStr := chi.URLParam(r, "id")
	requestID, err := uuid.Parse(requestIDStr)
	if err != nil {
		pkghttp.WriteBadRequest(w, "invalid request ID")
		return
	}

	// Confirm recovery
	err = h.service.ConfirmRecovery(r.Context(), requestID, confirmerID)
	if err != nil {
		h.logger.Error("failed to confirm recovery",
			slog.Any("request_id", requestID),
			slog.Any("confirmer_id", confirmerID),
			slog.Any("error", err))

		if err.Error() == "only admins can confirm recovery" {
			pkghttp.WriteForbidden(w, "insufficient privileges")
			return
		}

		if err.Error() == "invalid confirmation: must be different admin or request not pending" {
			pkghttp.WriteForbidden(w, "cannot confirm your own request or request is not pending")
			return
		}

		pkghttp.WriteInternalError(w, "failed to confirm recovery")
		return
	}

	// Return success
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"status":  "confirmed",
		"message": "recovery request confirmed successfully",
	})
}

// ExecuteRecovery executes the recovery (disables MFA)
// POST /admin/mfa/recovery/{id}/execute
func (h *MFARecoveryHandler) ExecuteRecovery(w http.ResponseWriter, r *http.Request) {
	// Extract admin from context
	claims := auth.GetUserFromContext(r)
	if claims == nil {
		pkghttp.WriteUnauthorized(w, "authentication required")
		return
	}

	executorID, err := uuid.Parse(claims.UserID)
	if err != nil {
		h.logger.Error("invalid executor ID", slog.Any("error", err))
		pkghttp.WriteInternalError(w, "invalid user ID")
		return
	}

	// Get request ID from URL
	requestIDStr := chi.URLParam(r, "id")
	requestID, err := uuid.Parse(requestIDStr)
	if err != nil {
		pkghttp.WriteBadRequest(w, "invalid request ID")
		return
	}

	// Execute recovery
	err = h.service.ExecuteRecovery(r.Context(), requestID, executorID)
	if err != nil {
		h.logger.Error("failed to execute recovery",
			slog.Any("request_id", requestID),
			slog.Any("executor_id", executorID),
			slog.Any("error", err))

		if err.Error() == "only admins can execute recovery" {
			pkghttp.WriteForbidden(w, "insufficient privileges")
			return
		}

		if err.Error() == "recovery request must be confirmed before execution" {
			pkghttp.WriteBadRequest(w, "recovery request must be confirmed before execution")
			return
		}

		if err.Error() == "recovery request has expired" {
			pkghttp.WriteBadRequest(w, "recovery request has expired")
			return
		}

		pkghttp.WriteInternalError(w, "failed to execute recovery")
		return
	}

	// Return success
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"status":  "executed",
		"message": "MFA has been disabled for the user",
	})
}

// ListPendingRecoveries lists all pending recovery requests
// GET /admin/mfa/recovery
func (h *MFARecoveryHandler) ListPendingRecoveries(w http.ResponseWriter, r *http.Request) {
	// Get pagination params
	limitStr := r.URL.Query().Get("limit")
	offsetStr := r.URL.Query().Get("offset")

	limit := 50 // Default
	if limitStr != "" {
		parsedLimit, err := strconv.Atoi(limitStr)
		if err == nil && parsedLimit > 0 && parsedLimit <= 100 {
			limit = parsedLimit
		}
	}

	offset := 0 // Default
	if offsetStr != "" {
		parsedOffset, err := strconv.Atoi(offsetStr)
		if err == nil && parsedOffset >= 0 {
			offset = parsedOffset
		}
	}

	// Get pending recoveries
	requests, err := h.service.ListPendingRecoveries(r.Context(), limit, offset)
	if err != nil {
		h.logger.Error("failed to list pending recoveries",
			slog.Any("error", err))
		pkghttp.WriteInternalError(w, "failed to list pending recoveries")
		return
	}

	// Convert to response DTOs
	responses := make([]RecoveryResponse, 0, len(requests))
	for _, req := range requests {
		responses = append(responses, toRecoveryResponse(req))
	}

	// Return list
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"requests": responses,
		"limit":    limit,
		"offset":   offset,
		"count":    len(responses),
	})
}

// CancelRecovery cancels a recovery request
// DELETE /admin/mfa/recovery/{id}
func (h *MFARecoveryHandler) CancelRecovery(w http.ResponseWriter, r *http.Request) {
	// Extract admin from context
	claims := auth.GetUserFromContext(r)
	if claims == nil {
		pkghttp.WriteUnauthorized(w, "authentication required")
		return
	}

	adminID, err := uuid.Parse(claims.UserID)
	if err != nil {
		h.logger.Error("invalid admin ID", slog.Any("error", err))
		pkghttp.WriteInternalError(w, "invalid user ID")
		return
	}

	// Get request ID from URL
	requestIDStr := chi.URLParam(r, "id")
	requestID, err := uuid.Parse(requestIDStr)
	if err != nil {
		pkghttp.WriteBadRequest(w, "invalid request ID")
		return
	}

	// Cancel recovery
	err = h.service.CancelRecovery(r.Context(), requestID, adminID)
	if err != nil {
		h.logger.Error("failed to cancel recovery",
			slog.Any("request_id", requestID),
			slog.Any("admin_id", adminID),
			slog.Any("error", err))

		if err.Error() == "only admins can cancel recovery" {
			pkghttp.WriteForbidden(w, "insufficient privileges")
			return
		}

		if err.Error() == "only initiator or confirmer can cancel" {
			pkghttp.WriteForbidden(w, "only the initiator or confirmer can cancel this request")
			return
		}

		pkghttp.WriteInternalError(w, "failed to cancel recovery")
		return
	}

	// Return 204 No Content
	w.WriteHeader(http.StatusNoContent)
}
