package auth

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/BradenHooton/kamino/internal/models"
	pkghttp "github.com/BradenHooton/kamino/pkg/http"
)

// MockResponseWriter for testing response interception
type MockResponseWriter struct {
	statusCode int
	headers    http.Header
	body       *bytes.Buffer
}

func NewMockResponseWriter() *MockResponseWriter {
	return &MockResponseWriter{
		statusCode: 0,
		headers:    make(http.Header),
		body:       new(bytes.Buffer),
	}
}

func (m *MockResponseWriter) Header() http.Header {
	return m.headers
}

func (m *MockResponseWriter) Write(data []byte) (int, error) {
	return m.body.Write(data)
}

func (m *MockResponseWriter) WriteHeader(statusCode int) {
	m.statusCode = statusCode
}

func TestResponseWriterWithStatus_CapturesStatusCode(t *testing.T) {
	// Test that responseWriterWithStatus captures the status code
	mockWriter := NewMockResponseWriter()
	wrapper := &responseWriterWithStatus{
		ResponseWriter: mockWriter,
		statusCode:     0,
		written:        false,
	}

	// Call WriteHeader with 404
	wrapper.WriteHeader(404)

	// Verify status code captured
	if wrapper.statusCode != 404 {
		t.Errorf("expected statusCode 404, got %d", wrapper.statusCode)
	}

	// Verify underlying writer received the header
	if mockWriter.statusCode != 404 {
		t.Errorf("expected underlying writer to receive 404, got %d", mockWriter.statusCode)
	}
}

func TestResponseWriterWithStatus_DefaultStatus200(t *testing.T) {
	// Test that statusCode defaults to 200 when WriteHeader not called
	mockWriter := NewMockResponseWriter()
	wrapper := &responseWriterWithStatus{
		ResponseWriter: mockWriter,
		statusCode:     0,
		written:        false,
	}

	// Call Write without WriteHeader
	wrapper.Write([]byte("test data"))

	// Verify status code defaults to 200
	if wrapper.statusCode != 200 {
		t.Errorf("expected default statusCode 200, got %d", wrapper.statusCode)
	}
}

func TestResponseWriterWithStatus_IgnoresDuplicateWrites(t *testing.T) {
	// Test that WriteHeader called multiple times only sets status once
	mockWriter := NewMockResponseWriter()
	wrapper := &responseWriterWithStatus{
		ResponseWriter: mockWriter,
		statusCode:     0,
		written:        false,
	}

	// Call WriteHeader with 200
	wrapper.WriteHeader(200)
	wrapper.written = true // Simulate write flag

	// Try to call WriteHeader again with 404 (should be ignored)
	wrapper.WriteHeader(404)

	// Verify original status code remains 200
	if wrapper.statusCode != 200 {
		t.Errorf("expected statusCode 200 (first write wins), got %d", wrapper.statusCode)
	}
}

func TestResponseWriterWithStatus_HeadersPassthrough(t *testing.T) {
	// Test that Header() passes through to underlying writer
	mockWriter := NewMockResponseWriter()
	wrapper := &responseWriterWithStatus{
		ResponseWriter: mockWriter,
		statusCode:     0,
		written:        false,
	}

	// Get headers from wrapper and set a value
	headers := wrapper.Header()
	headers.Set("Content-Type", "application/json")

	// Verify header set in underlying writer
	if mockWriter.Header().Get("Content-Type") != "application/json" {
		t.Errorf("expected Content-Type to be passed to underlying writer")
	}
}

func TestResponseWriterWithStatus_WritePassthrough(t *testing.T) {
	// Test that Write() passes through to underlying writer
	mockWriter := NewMockResponseWriter()
	wrapper := &responseWriterWithStatus{
		ResponseWriter: mockWriter,
		statusCode:     0,
		written:        false,
	}

	// Write data through wrapper
	testData := []byte("test response body")
	wrapper.Write(testData)

	// Verify data passed to underlying writer
	if mockWriter.body.String() != "test response body" {
		t.Errorf("expected data to be written to underlying writer, got %s", mockWriter.body.String())
	}
}

// MockAPIKeyValidator for testing
type MockAPIKeyValidator struct {
	apiKey *models.APIKey
	err    error
}

func (m *MockAPIKeyValidator) ValidateAPIKey(ctx context.Context, plainKey string) (*models.APIKey, error) {
	return m.apiKey, m.err
}

// MockAuditLogger for testing API key audit logging
type MockAuditLogger struct {
	capturedIPAddress *string
	lastCall          *APIKeyUsageCall
}

type APIKeyUsageCall struct {
	ActorID        string
	KeyID          string
	KeyPrefix      string
	Endpoint       string
	Method         string
	RequiredScopes []string
	StatusCode     int
	IPAddress      *string
	UserAgent      *string
}

func (m *MockAuditLogger) LogAPIKeyUsage(
	ctx context.Context,
	actorID string,
	keyID string,
	keyPrefix string,
	endpoint string,
	method string,
	requiredScopes []string,
	statusCode int,
	ipAddress *string,
	userAgent *string,
) {
	m.lastCall = &APIKeyUsageCall{
		ActorID:        actorID,
		KeyID:          keyID,
		KeyPrefix:      keyPrefix,
		Endpoint:       endpoint,
		Method:         method,
		RequiredScopes: requiredScopes,
		StatusCode:     statusCode,
		IPAddress:      ipAddress,
		UserAgent:      userAgent,
	}
	m.capturedIPAddress = ipAddress
}

// TestAuthMiddlewareWithAPIKey_DirectConnection_IgnoresSpoofedHeaders
// Test 5.1: Verify X-Forwarded-For from non-trusted sources is ignored
func TestAuthMiddlewareWithAPIKey_DirectConnection_IgnoresSpoofedHeaders(t *testing.T) {
	mockValidator := &MockAPIKeyValidator{
		apiKey: &models.APIKey{
			ID:        "key-123",
			UserID:    "user-123",
			KeyPrefix: "kmn_",
			Scopes:    []string{"users.read"},
		},
	}
	auditLogger := &MockAuditLogger{}

	// Create middleware with empty TrustedProxies (direct connection, don't trust headers)
	ipConfig := &pkghttp.IPConfig{
		TrustedProxies: []string{}, // Empty = no trusted proxies
	}

	middleware := AuthMiddlewareWithAPIKey(nil, mockValidator, nil, RevocationConfig{}, auditLogger, ipConfig)

	// Create request with spoofed X-Forwarded-For header
	req := httptest.NewRequest("GET", "/users/123", nil)
	req.RemoteAddr = "203.0.113.10:54321"
	req.Header.Set("X-API-Key", "kmn_valid_key_64_chars_here_1234567890abcdef1234567890abcdef")
	req.Header.Set("X-Forwarded-For", "1.2.3.4") // Attacker tries to spoof IP

	w := httptest.NewRecorder()
	nextCalled := false
	nextHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nextCalled = true
		w.WriteHeader(http.StatusOK)
	})

	middleware(nextHandler).ServeHTTP(w, req)

	// Verify that the real IP (203.0.113.10) was logged, not the spoofed IP
	if auditLogger.lastCall == nil {
		t.Fatalf("expected audit logger to be called")
	}

	if auditLogger.lastCall.IPAddress == nil {
		t.Fatalf("expected IPAddress to be captured")
	}

	if *auditLogger.lastCall.IPAddress != "203.0.113.10" {
		t.Errorf("expected IP 203.0.113.10 (real client), got %s (spoofed header was accepted)", *auditLogger.lastCall.IPAddress)
	}

	if !nextCalled {
		t.Errorf("expected next handler to be called")
	}
}

// TestAuthMiddlewareWithAPIKey_TrustedProxy_UsesXForwardedFor
// Test 5.2: Verify X-Forwarded-For is trusted from configured proxies
func TestAuthMiddlewareWithAPIKey_TrustedProxy_UsesXForwardedFor(t *testing.T) {
	mockValidator := &MockAPIKeyValidator{
		apiKey: &models.APIKey{
			ID:        "key-456",
			UserID:    "user-123",
			KeyPrefix: "kmn_",
			Scopes:    []string{"users.read"},
		},
	}
	auditLogger := &MockAuditLogger{}

	// Create middleware with 10.0.0.0/8 as trusted proxy CIDR
	ipConfig := &pkghttp.IPConfig{
		TrustedProxies: []string{"10.0.0.0/8"},
	}

	middleware := AuthMiddlewareWithAPIKey(nil, mockValidator, nil, RevocationConfig{}, auditLogger, ipConfig)

	// Create request from trusted proxy with X-Forwarded-For header
	req := httptest.NewRequest("GET", "/users/123", nil)
	req.RemoteAddr = "10.0.0.5:54321" // Request comes from trusted proxy
	req.Header.Set("X-API-Key", "kmn_valid_key_64_chars_here_1234567890abcdef1234567890abcdef")
	req.Header.Set("X-Forwarded-For", "203.0.113.42") // Real client IP in header

	w := httptest.NewRecorder()
	nextCalled := false
	nextHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nextCalled = true
		w.WriteHeader(http.StatusOK)
	})

	middleware(nextHandler).ServeHTTP(w, req)

	// Verify that the X-Forwarded-For IP (203.0.113.42) was logged
	if auditLogger.lastCall == nil {
		t.Fatalf("expected audit logger to be called")
	}

	if auditLogger.lastCall.IPAddress == nil {
		t.Fatalf("expected IPAddress to be captured")
	}

	if *auditLogger.lastCall.IPAddress != "203.0.113.42" {
		t.Errorf("expected IP 203.0.113.42 from X-Forwarded-For header, got %s", *auditLogger.lastCall.IPAddress)
	}

	if !nextCalled {
		t.Errorf("expected next handler to be called")
	}
}

// TestAuthMiddlewareWithAPIKey_NilIPConfig_FailsSecurely
// Test 5.3: Verify graceful degradation when ipConfig=nil
func TestAuthMiddlewareWithAPIKey_NilIPConfig_FailsSecurely(t *testing.T) {
	mockValidator := &MockAPIKeyValidator{
		apiKey: &models.APIKey{
			ID:        "key-789",
			UserID:    "user-123",
			KeyPrefix: "kmn_",
			Scopes:    []string{"users.read"},
		},
	}
	auditLogger := &MockAuditLogger{}

	// Create middleware with nil ipConfig (should degrade gracefully)
	middleware := AuthMiddlewareWithAPIKey(nil, mockValidator, nil, RevocationConfig{}, auditLogger, nil)

	// Create request with spoofed headers
	req := httptest.NewRequest("GET", "/users/123", nil)
	req.RemoteAddr = "203.0.113.10:54321"
	req.Header.Set("X-API-Key", "kmn_valid_key_64_chars_here_1234567890abcdef1234567890abcdef")
	req.Header.Set("X-Forwarded-For", "1.2.3.4") // Spoofed header

	w := httptest.NewRecorder()
	nextCalled := false
	nextHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nextCalled = true
		w.WriteHeader(http.StatusOK)
	})

	middleware(nextHandler).ServeHTTP(w, req)

	// Verify that RemoteAddr was used (secure fallback when ipConfig=nil)
	if auditLogger.lastCall == nil {
		t.Fatalf("expected audit logger to be called")
	}

	if auditLogger.lastCall.IPAddress == nil {
		t.Fatalf("expected IPAddress to be captured")
	}

	if *auditLogger.lastCall.IPAddress != "203.0.113.10" {
		t.Errorf("expected IP 203.0.113.10 from RemoteAddr (ipConfig=nil fallback), got %s", *auditLogger.lastCall.IPAddress)
	}

	if !nextCalled {
		t.Errorf("expected next handler to be called")
	}
}

// TestAuthMiddlewareWithAPIKey_EmptyTrustedProxies_IgnoresHeaders
// Test 5.4: Verify empty TrustedProxies list doesn't trust headers
func TestAuthMiddlewareWithAPIKey_EmptyTrustedProxies_IgnoresHeaders(t *testing.T) {
	mockValidator := &MockAPIKeyValidator{
		apiKey: &models.APIKey{
			ID:        "key-010",
			UserID:    "user-123",
			KeyPrefix: "kmn_",
			Scopes:    []string{"users.read"},
		},
	}
	auditLogger := &MockAuditLogger{}

	// Create middleware with explicitly empty TrustedProxies (secure default)
	ipConfig := &pkghttp.IPConfig{
		TrustedProxies: []string{}, // Empty list = don't trust any headers
	}

	middleware := AuthMiddlewareWithAPIKey(nil, mockValidator, nil, RevocationConfig{}, auditLogger, ipConfig)

	// Create request with X-Forwarded-For header
	req := httptest.NewRequest("GET", "/users/123", nil)
	req.RemoteAddr = "203.0.113.10:54321"
	req.Header.Set("X-API-Key", "kmn_valid_key_64_chars_here_1234567890abcdef1234567890abcdef")
	req.Header.Set("X-Forwarded-For", "1.2.3.4")
	req.Header.Set("X-Real-IP", "1.2.3.5")

	w := httptest.NewRecorder()
	nextCalled := false
	nextHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nextCalled = true
		w.WriteHeader(http.StatusOK)
	})

	middleware(nextHandler).ServeHTTP(w, req)

	// Verify that RemoteAddr was used (headers ignored when TrustedProxies is empty)
	if auditLogger.lastCall == nil {
		t.Fatalf("expected audit logger to be called")
	}

	if auditLogger.lastCall.IPAddress == nil {
		t.Fatalf("expected IPAddress to be captured")
	}

	if *auditLogger.lastCall.IPAddress != "203.0.113.10" {
		t.Errorf("expected IP 203.0.113.10 from RemoteAddr (empty TrustedProxies), got %s", *auditLogger.lastCall.IPAddress)
	}

	if !nextCalled {
		t.Errorf("expected next handler to be called")
	}
}

// TestAuthMiddlewareWithAPIKey_IPv6TrustedProxy_ExtractsCorrectly
// Test 5.5: Verify IPv6 addresses work with CIDR validation
func TestAuthMiddlewareWithAPIKey_IPv6TrustedProxy_ExtractsCorrectly(t *testing.T) {
	mockValidator := &MockAPIKeyValidator{
		apiKey: &models.APIKey{
			ID:        "key-ipv6",
			UserID:    "user-123",
			KeyPrefix: "kmn_",
			Scopes:    []string{"users.read"},
		},
	}
	auditLogger := &MockAuditLogger{}

	// Create middleware with IPv6 CIDR for localhost
	ipConfig := &pkghttp.IPConfig{
		TrustedProxies: []string{"::1/128"}, // IPv6 localhost
	}

	middleware := AuthMiddlewareWithAPIKey(nil, mockValidator, nil, RevocationConfig{}, auditLogger, ipConfig)

	// Create request from IPv6 trusted proxy
	req := httptest.NewRequest("GET", "/users/123", nil)
	req.RemoteAddr = "[::1]:54321" // IPv6 localhost with port
	req.Header.Set("X-API-Key", "kmn_valid_key_64_chars_here_1234567890abcdef1234567890abcdef")
	req.Header.Set("X-Forwarded-For", "2001:db8::1") // Real IPv6 client

	w := httptest.NewRecorder()
	nextCalled := false
	nextHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nextCalled = true
		w.WriteHeader(http.StatusOK)
	})

	middleware(nextHandler).ServeHTTP(w, req)

	// Verify that the IPv6 X-Forwarded-For address was logged
	if auditLogger.lastCall == nil {
		t.Fatalf("expected audit logger to be called")
	}

	if auditLogger.lastCall.IPAddress == nil {
		t.Fatalf("expected IPAddress to be captured")
	}

	if *auditLogger.lastCall.IPAddress != "2001:db8::1" {
		t.Errorf("expected IPv6 address 2001:db8::1 from X-Forwarded-For, got %s", *auditLogger.lastCall.IPAddress)
	}

	if !nextCalled {
		t.Errorf("expected next handler to be called")
	}
}
