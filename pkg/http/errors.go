package http

import (
	"encoding/json"
	"net/http"
)

// ErrorResponse represents a standard API error response
type ErrorResponse struct {
	Error   string `json:"error"`            // Machine-readable error code
	Message string `json:"message"`          // Human-readable message
	Details string `json:"details,omitempty"` // Optional additional context
}

// WriteError writes a JSON error response with the given status code
func WriteError(w http.ResponseWriter, statusCode int, errorCode, message string) {
	WriteErrorWithDetails(w, statusCode, errorCode, message, "")
}

// WriteErrorWithDetails writes a JSON error response with additional details
func WriteErrorWithDetails(w http.ResponseWriter, statusCode int, errorCode, message, details string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)

	resp := ErrorResponse{
		Error:   errorCode,
		Message: message,
		Details: details,
	}

	// Log encoding errors but don't expose them to client
	_ = json.NewEncoder(w).Encode(resp)
}

// Common error writers for consistency
func WriteBadRequest(w http.ResponseWriter, message string) {
	WriteError(w, http.StatusBadRequest, "bad_request", message)
}

func WriteUnauthorized(w http.ResponseWriter, message string) {
	WriteError(w, http.StatusUnauthorized, "unauthorized", message)
}

func WriteForbidden(w http.ResponseWriter, message string) {
	WriteError(w, http.StatusForbidden, "forbidden", message)
}

func WriteNotFound(w http.ResponseWriter, message string) {
	WriteError(w, http.StatusNotFound, "not_found", message)
}

func WriteConflict(w http.ResponseWriter, message string) {
	WriteError(w, http.StatusConflict, "conflict", message)
}

func WriteTooManyRequests(w http.ResponseWriter, message string) {
	WriteError(w, http.StatusTooManyRequests, "rate_limit_exceeded", message)
}

func WriteInternalError(w http.ResponseWriter, message string) {
	WriteError(w, http.StatusInternalServerError, "internal_error", message)
}
