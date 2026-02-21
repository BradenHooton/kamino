package middleware

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/BradenHooton/kamino/internal/auth"
	"github.com/BradenHooton/kamino/internal/models"
)

// TestRateLimitByUserID_ExtractsUserIDFromContext verifies that rate limiting extracts user ID from context
func TestRateLimitByUserID_ExtractsUserIDFromContext(t *testing.T) {
	config := AuthenticatedRateLimitConfig{
		ReadOperationsPerMinute:  100,
		WriteOperationsPerMinute: 30,
		AdminOperationsPerMinute: 60,
	}
	middleware := RateLimitByUserID(config, "read")

	claims := &models.TokenClaims{UserID: "user-123", Type: "access"}
	handler := middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/test", nil)
	req = req.WithContext(context.WithValue(req.Context(), auth.UserContextKey, claims))
	recorder := httptest.NewRecorder()

	handler.ServeHTTP(recorder, req)
	// First request should succeed
	if recorder.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", recorder.Code)
	}
}

// TestRateLimitByUserID_FallbackToIPWhenNoUserID verifies fallback to IP-based when UserID unavailable
func TestRateLimitByUserID_FallbackToIPWhenNoUserID(t *testing.T) {
	config := AuthenticatedRateLimitConfig{
		ReadOperationsPerMinute: 100,
	}
	middleware := RateLimitByUserID(config, "read")

	handler := middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	// No user context set - should fallback to IP
	req := httptest.NewRequest("GET", "/test", nil)
	req.RemoteAddr = "192.168.1.1:8080"
	recorder := httptest.NewRecorder()

	handler.ServeHTTP(recorder, req)
	// First request should succeed (uses IP-based rate limiting)
	if recorder.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", recorder.Code)
	}
}

// TestRateLimitByUserID_EnforcesReadLimit verifies 100 req/min limit for read operations
func TestRateLimitByUserID_EnforcesReadLimit(t *testing.T) {
	config := AuthenticatedRateLimitConfig{
		ReadOperationsPerMinute: 100,
	}
	middleware := RateLimitByUserID(config, "read")

	claims := &models.TokenClaims{UserID: "user-read-test", Type: "access"}
	handler := middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	// Make 100 successful requests
	for i := 0; i < 100; i++ {
		req := httptest.NewRequest("GET", "/test", nil)
		req = req.WithContext(context.WithValue(req.Context(), auth.UserContextKey, claims))
		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, req)

		if recorder.Code != http.StatusOK {
			t.Errorf("request %d failed with status %d, expected 200", i+1, recorder.Code)
		}
	}

	// 101st request should be rate limited
	req := httptest.NewRequest("GET", "/test", nil)
	req = req.WithContext(context.WithValue(req.Context(), auth.UserContextKey, claims))
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, req)

	if recorder.Code != http.StatusTooManyRequests {
		t.Errorf("expected status %d (too many requests), got %d", http.StatusTooManyRequests, recorder.Code)
	}
}

// TestRateLimitByUserID_EnforcesWriteLimit verifies 30 req/min limit for write operations
func TestRateLimitByUserID_EnforcesWriteLimit(t *testing.T) {
	config := AuthenticatedRateLimitConfig{
		WriteOperationsPerMinute: 30,
	}
	middleware := RateLimitByUserID(config, "write")

	claims := &models.TokenClaims{UserID: "user-write-test", Type: "access"}
	handler := middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	// Make 30 successful requests
	for i := 0; i < 30; i++ {
		req := httptest.NewRequest("POST", "/test", nil)
		req = req.WithContext(context.WithValue(req.Context(), auth.UserContextKey, claims))
		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, req)

		if recorder.Code != http.StatusOK {
			t.Errorf("request %d failed with status %d, expected 200", i+1, recorder.Code)
		}
	}

	// 31st request should be rate limited
	req := httptest.NewRequest("POST", "/test", nil)
	req = req.WithContext(context.WithValue(req.Context(), auth.UserContextKey, claims))
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, req)

	if recorder.Code != http.StatusTooManyRequests {
		t.Errorf("expected status %d (too many requests), got %d", http.StatusTooManyRequests, recorder.Code)
	}
}

// TestRateLimitByUserID_EnforcesAdminLimit verifies 60 req/min limit for admin operations
func TestRateLimitByUserID_EnforcesAdminLimit(t *testing.T) {
	config := AuthenticatedRateLimitConfig{
		AdminOperationsPerMinute: 60,
	}
	middleware := RateLimitByUserID(config, "admin")

	claims := &models.TokenClaims{UserID: "user-admin-test", Type: "access"}
	handler := middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	// Make 60 successful requests
	for i := 0; i < 60; i++ {
		req := httptest.NewRequest("GET", "/test", nil)
		req = req.WithContext(context.WithValue(req.Context(), auth.UserContextKey, claims))
		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, req)

		if recorder.Code != http.StatusOK {
			t.Errorf("request %d failed with status %d, expected 200", i+1, recorder.Code)
		}
	}

	// 61st request should be rate limited
	req := httptest.NewRequest("GET", "/test", nil)
	req = req.WithContext(context.WithValue(req.Context(), auth.UserContextKey, claims))
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, req)

	if recorder.Code != http.StatusTooManyRequests {
		t.Errorf("expected status %d (too many requests), got %d", http.StatusTooManyRequests, recorder.Code)
	}
}

// TestRateLimitByUserID_Returns429AfterLimit verifies HTTP 429 response format
func TestRateLimitByUserID_Returns429AfterLimit(t *testing.T) {
	config := AuthenticatedRateLimitConfig{
		WriteOperationsPerMinute: 1,
	}
	middleware := RateLimitByUserID(config, "write")

	claims := &models.TokenClaims{UserID: "user-429-test", Type: "access"}
	handler := middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	// First request succeeds
	req := httptest.NewRequest("POST", "/test", nil)
	req = req.WithContext(context.WithValue(req.Context(), auth.UserContextKey, claims))
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, req)

	if recorder.Code != http.StatusOK {
		t.Errorf("first request failed with status %d", recorder.Code)
	}

	// Second request is rate limited
	req = httptest.NewRequest("POST", "/test", nil)
	req = req.WithContext(context.WithValue(req.Context(), auth.UserContextKey, claims))
	recorder = httptest.NewRecorder()
	handler.ServeHTTP(recorder, req)

	if recorder.Code != http.StatusTooManyRequests {
		t.Errorf("expected 429, got %d", recorder.Code)
	}

	// Verify Content-Type is JSON
	contentType := recorder.Header().Get("Content-Type")
	if contentType != "application/json" {
		t.Errorf("expected Content-Type application/json, got %s", contentType)
	}

	// Verify response body contains error message
	body := recorder.Body.String()
	if body != `{"error":"rate_limit_exceeded","message":"Too many requests"}` {
		t.Errorf("unexpected response body: %s", body)
	}
}

// TestRateLimitByUserID_IsolatesUserBuckets verifies separate rate limits per user
func TestRateLimitByUserID_IsolatesUserBuckets(t *testing.T) {
	config := AuthenticatedRateLimitConfig{
		ReadOperationsPerMinute: 10,
	}
	middleware := RateLimitByUserID(config, "read")

	handler := middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	userAID := "user-a-isolation"
	userBID := "user-b-isolation"

	claimsA := &models.TokenClaims{UserID: userAID, Type: "access"}
	claimsB := &models.TokenClaims{UserID: userBID, Type: "access"}

	// User A makes 10 requests (hits limit)
	for i := 0; i < 10; i++ {
		req := httptest.NewRequest("GET", "/test", nil)
		req = req.WithContext(context.WithValue(req.Context(), auth.UserContextKey, claimsA))
		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, req)
		if recorder.Code != http.StatusOK {
			t.Errorf("user A request %d failed", i+1)
		}
	}

	// User B should still be able to make requests (independent bucket)
	req := httptest.NewRequest("GET", "/test", nil)
	req = req.WithContext(context.WithValue(req.Context(), auth.UserContextKey, claimsB))
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, req)

	if recorder.Code != http.StatusOK {
		t.Errorf("user B should have independent rate limit, got status %d", recorder.Code)
	}
}

// TestRateLimitByUserID_WorksWithJWTClaims verifies rate limiting with JWT token claims (Type="access")
func TestRateLimitByUserID_WorksWithJWTClaims(t *testing.T) {
	config := AuthenticatedRateLimitConfig{
		ReadOperationsPerMinute: 5,
	}
	middleware := RateLimitByUserID(config, "read")

	// JWT token claims
	claims := &models.TokenClaims{
		UserID: "user-jwt-test",
		Type:   "access",
	}

	handler := middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	// Make 5 requests
	for i := 0; i < 5; i++ {
		req := httptest.NewRequest("GET", "/test", nil)
		req = req.WithContext(context.WithValue(req.Context(), auth.UserContextKey, claims))
		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, req)
		if recorder.Code != http.StatusOK {
			t.Errorf("JWT request %d failed", i+1)
		}
	}

	// 6th request should be rate limited
	req := httptest.NewRequest("GET", "/test", nil)
	req = req.WithContext(context.WithValue(req.Context(), auth.UserContextKey, claims))
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, req)

	if recorder.Code != http.StatusTooManyRequests {
		t.Errorf("JWT rate limiting failed, expected 429, got %d", recorder.Code)
	}
}

// TestRateLimitByUserID_WorksWithAPIKeyClaims verifies rate limiting with API key claims (Type="api_key")
func TestRateLimitByUserID_WorksWithAPIKeyClaims(t *testing.T) {
	config := AuthenticatedRateLimitConfig{
		ReadOperationsPerMinute: 5,
	}
	middleware := RateLimitByUserID(config, "read")

	// API key claims
	claims := &models.TokenClaims{
		UserID: "user-api-key-test",
		Type:   "api_key",
	}

	handler := middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	// Make 5 requests
	for i := 0; i < 5; i++ {
		req := httptest.NewRequest("GET", "/test", nil)
		req = req.WithContext(context.WithValue(req.Context(), auth.UserContextKey, claims))
		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, req)
		if recorder.Code != http.StatusOK {
			t.Errorf("API key request %d failed", i+1)
		}
	}

	// 6th request should be rate limited
	req := httptest.NewRequest("GET", "/test", nil)
	req = req.WithContext(context.WithValue(req.Context(), auth.UserContextKey, claims))
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, req)

	if recorder.Code != http.StatusTooManyRequests {
		t.Errorf("API key rate limiting failed, expected 429, got %d", recorder.Code)
	}
}
