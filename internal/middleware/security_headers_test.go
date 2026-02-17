package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestSecurityHeaders_Production(t *testing.T) {
	handler := SecurityHeaders(SecurityHeadersConfig{Env: "production"})

	testHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest("GET", "/", nil)
	w := httptest.NewRecorder()

	handler(testHandler).ServeHTTP(w, req)

	tests := []struct {
		header   string
		expected string
	}{
		{"X-Frame-Options", "DENY"},
		{"X-Content-Type-Options", "nosniff"},
		{"X-XSS-Protection", "1; mode=block"},
		{"Referrer-Policy", "strict-origin-when-cross-origin"},
	}

	for _, tt := range tests {
		if got := w.Header().Get(tt.header); got != tt.expected {
			t.Errorf("Header %s: got %q, want %q", tt.header, got, tt.expected)
		}
	}

	// CSP should be present (strict in production)
	if csp := w.Header().Get("Content-Security-Policy"); csp == "" {
		t.Error("Content-Security-Policy header missing")
	} else if cspHasDefaultSrc := hasString(csp, "default-src 'self'"); !cspHasDefaultSrc {
		t.Errorf("CSP should be strict in production: %s", csp)
	}

	// Permissions-Policy should be present
	if pp := w.Header().Get("Permissions-Policy"); pp == "" {
		t.Error("Permissions-Policy header missing")
	}
}

func TestSecurityHeaders_Development(t *testing.T) {
	handler := SecurityHeaders(SecurityHeadersConfig{Env: "development"})

	testHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest("GET", "/", nil)
	w := httptest.NewRecorder()

	handler(testHandler).ServeHTTP(w, req)

	// Basic headers should still be present
	if got := w.Header().Get("X-Frame-Options"); got != "DENY" {
		t.Errorf("X-Frame-Options: got %q, want DENY", got)
	}

	// CSP should be more permissive in development
	if csp := w.Header().Get("Content-Security-Policy"); csp == "" {
		t.Error("Content-Security-Policy header missing")
	} else if cspHasUnsafeInline := hasString(csp, "unsafe-inline"); !cspHasUnsafeInline {
		t.Errorf("CSP should allow unsafe-inline in development: %s", csp)
	}
}

func hasString(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
