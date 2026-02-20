package http_test

import (
	"encoding/json"
	"net/http/httptest"
	"testing"

	pkghttp "github.com/BradenHooton/kamino/pkg/http"
	"github.com/stretchr/testify/assert"
)

func TestWriteError(t *testing.T) {
	w := httptest.NewRecorder()

	pkghttp.WriteError(w, 400, "test_error", "Test message")

	assert.Equal(t, 400, w.Code)
	assert.Equal(t, "application/json", w.Header().Get("Content-Type"))

	var resp pkghttp.ErrorResponse
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	assert.NoError(t, err)
	assert.Equal(t, "test_error", resp.Error)
	assert.Equal(t, "Test message", resp.Message)
	assert.Empty(t, resp.Details)
}

func TestWriteErrorWithDetails(t *testing.T) {
	w := httptest.NewRecorder()

	pkghttp.WriteErrorWithDetails(w, 400, "test_error", "Test message", "Additional details")

	assert.Equal(t, 400, w.Code)

	var resp pkghttp.ErrorResponse
	json.Unmarshal(w.Body.Bytes(), &resp)
	assert.Equal(t, "test_error", resp.Error)
	assert.Equal(t, "Test message", resp.Message)
	assert.Equal(t, "Additional details", resp.Details)
}

func TestWriteBadRequest(t *testing.T) {
	w := httptest.NewRecorder()
	pkghttp.WriteBadRequest(w, "Invalid input")

	assert.Equal(t, 400, w.Code)

	var resp pkghttp.ErrorResponse
	json.Unmarshal(w.Body.Bytes(), &resp)
	assert.Equal(t, "bad_request", resp.Error)
	assert.Equal(t, "Invalid input", resp.Message)
}

func TestWriteUnauthorized(t *testing.T) {
	w := httptest.NewRecorder()
	pkghttp.WriteUnauthorized(w, "Invalid credentials")

	assert.Equal(t, 401, w.Code)

	var resp pkghttp.ErrorResponse
	json.Unmarshal(w.Body.Bytes(), &resp)
	assert.Equal(t, "unauthorized", resp.Error)
	assert.Equal(t, "Invalid credentials", resp.Message)
}

func TestWriteForbidden(t *testing.T) {
	w := httptest.NewRecorder()
	pkghttp.WriteForbidden(w, "Access denied")

	assert.Equal(t, 403, w.Code)

	var resp pkghttp.ErrorResponse
	json.Unmarshal(w.Body.Bytes(), &resp)
	assert.Equal(t, "forbidden", resp.Error)
	assert.Equal(t, "Access denied", resp.Message)
}

func TestWriteNotFound(t *testing.T) {
	w := httptest.NewRecorder()
	pkghttp.WriteNotFound(w, "Resource not found")

	assert.Equal(t, 404, w.Code)

	var resp pkghttp.ErrorResponse
	json.Unmarshal(w.Body.Bytes(), &resp)
	assert.Equal(t, "not_found", resp.Error)
	assert.Equal(t, "Resource not found", resp.Message)
}

func TestWriteConflict(t *testing.T) {
	w := httptest.NewRecorder()
	pkghttp.WriteConflict(w, "Email already exists")

	assert.Equal(t, 409, w.Code)

	var resp pkghttp.ErrorResponse
	json.Unmarshal(w.Body.Bytes(), &resp)
	assert.Equal(t, "conflict", resp.Error)
	assert.Equal(t, "Email already exists", resp.Message)
}

func TestWriteTooManyRequests(t *testing.T) {
	w := httptest.NewRecorder()
	pkghttp.WriteTooManyRequests(w, "Too many requests")

	assert.Equal(t, 429, w.Code)

	var resp pkghttp.ErrorResponse
	json.Unmarshal(w.Body.Bytes(), &resp)
	assert.Equal(t, "rate_limit_exceeded", resp.Error)
	assert.Equal(t, "Too many requests", resp.Message)
}

func TestWriteInternalError(t *testing.T) {
	w := httptest.NewRecorder()
	pkghttp.WriteInternalError(w, "Internal server error")

	assert.Equal(t, 500, w.Code)

	var resp pkghttp.ErrorResponse
	json.Unmarshal(w.Body.Bytes(), &resp)
	assert.Equal(t, "internal_error", resp.Error)
	assert.Equal(t, "Internal server error", resp.Message)
}

func TestErrorResponseJSON(t *testing.T) {
	w := httptest.NewRecorder()
	pkghttp.WriteError(w, 401, "unauthorized", "Invalid token")

	// Verify valid JSON is written
	var resp map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	assert.NoError(t, err)

	// Verify JSON structure
	assert.Contains(t, resp, "error")
	assert.Contains(t, resp, "message")
	assert.Equal(t, "unauthorized", resp["error"])
	assert.Equal(t, "Invalid token", resp["message"])
}
