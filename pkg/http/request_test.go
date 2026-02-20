package http_test

import (
	"net/http/httptest"
	"testing"

	pkghttp "github.com/BradenHooton/kamino/pkg/http"
	"github.com/stretchr/testify/assert"
)

// CRITICAL SECURITY TEST #2: IP Spoofing Vulnerability
// Verify that X-Forwarded-For and X-Real-IP headers are only trusted from configured proxies

func TestExtractClientIP_DirectConnection_IgnoresHeaders(t *testing.T) {
	// Simulate direct client connection (not from trusted proxy)
	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "203.0.113.10:54321" // Direct client IP

	// Attacker tries to spoof their IP via X-Forwarded-For
	req.Header.Set("X-Forwarded-For", "1.2.3.4, 5.6.7.8")
	req.Header.Set("X-Real-IP", "192.168.1.1")

	config := &pkghttp.IPConfig{
		TrustedProxies: []string{
			"10.0.0.0/8",      // Internal network
			"172.16.0.0/12",   // Internal network
			"127.0.0.1/32",    // Localhost (only if reverse proxy on same machine)
		},
	}

	ip := pkghttp.ExtractClientIP(req, config)

	// Should use RemoteAddr, NOT X-Forwarded-For (which is spoofed)
	assert.Equal(t, "203.0.113.10", ip, "Should extract IP from RemoteAddr when not from trusted proxy")
}

func TestExtractClientIP_TrustedProxy_UsesXForwardedFor(t *testing.T) {
	// Simulate request from trusted proxy (e.g., CloudFlare, AWS ALB)
	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "10.0.0.5:54321" // Trusted proxy IP

	// Proxy correctly forwards original client IP in X-Forwarded-For
	req.Header.Set("X-Forwarded-For", "203.0.113.42, 10.0.0.5")
	req.Header.Set("X-Real-IP", "203.0.113.42")

	config := &pkghttp.IPConfig{
		TrustedProxies: []string{
			"10.0.0.0/8",       // Internal network (includes 10.0.0.5)
			"127.0.0.1/32",     // Localhost
		},
	}

	ip := pkghttp.ExtractClientIP(req, config)

	// Should extract from X-Forwarded-For since request is from trusted proxy
	assert.Equal(t, "203.0.113.42", ip, "Should extract from X-Forwarded-For when from trusted proxy")
}

func TestExtractClientIP_IPv6_TrustedProxy(t *testing.T) {
	// Simulate IPv6 request from trusted proxy
	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "[::1]:54321" // IPv6 localhost

	req.Header.Set("X-Forwarded-For", "2001:db8::1")

	config := &pkghttp.IPConfig{
		TrustedProxies: []string{
			"::1/128",           // IPv6 localhost
			"2001:db8::/32",     // IPv6 range
		},
	}

	ip := pkghttp.ExtractClientIP(req, config)

	// Should extract from X-Forwarded-For
	assert.Equal(t, "2001:db8::1", ip, "Should extract IPv6 from X-Forwarded-For when from trusted proxy")
}

func TestExtractClientIP_NoConfig_DefaultsSecurely(t *testing.T) {
	// When no config is provided (nil), should only trust RemoteAddr
	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "203.0.113.10:54321"

	req.Header.Set("X-Forwarded-For", "1.2.3.4, 5.6.7.8")
	req.Header.Set("X-Real-IP", "192.168.1.1")

	ip := pkghttp.ExtractClientIP(req, nil)

	// Should use RemoteAddr when no config provided
	assert.Equal(t, "203.0.113.10", ip, "Should default to RemoteAddr when no trusted proxies configured")
}

func TestExtractClientIP_EmptyConfig_DefaultsSecurely(t *testing.T) {
	// When empty proxy list is provided, should not trust headers
	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "203.0.113.10:54321"

	req.Header.Set("X-Forwarded-For", "1.2.3.4")

	config := &pkghttp.IPConfig{
		TrustedProxies: []string{}, // Empty trusted proxies list
	}

	ip := pkghttp.ExtractClientIP(req, config)

	// Should use RemoteAddr when no trusted proxies configured
	assert.Equal(t, "203.0.113.10", ip, "Should use RemoteAddr when trusted proxies list is empty")
}

func TestExtractClientIP_InvalidCIDR_IgnoresProxyCheck(t *testing.T) {
	// When CIDR ranges are invalid, should fail securely
	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "203.0.113.10:54321"

	req.Header.Set("X-Forwarded-For", "1.2.3.4")

	config := &pkghttp.IPConfig{
		TrustedProxies: []string{
			"invalid-cidr-range",
			"also-invalid",
		},
	}

	ip := pkghttp.ExtractClientIP(req, config)

	// Should fall back to RemoteAddr when CIDR parsing fails
	assert.Equal(t, "203.0.113.10", ip, "Should use RemoteAddr when CIDR ranges are invalid")
}

func TestExtractClientIP_MultipleIPs_UsesFirst(t *testing.T) {
	// When X-Forwarded-For has multiple IPs, use the first one
	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "10.0.0.5:54321" // Trusted proxy

	req.Header.Set("X-Forwarded-For", "203.0.113.42, 203.0.113.43, 10.0.0.5")

	config := &pkghttp.IPConfig{
		TrustedProxies: []string{"10.0.0.0/8"},
	}

	ip := pkghttp.ExtractClientIP(req, config)

	// Should extract the FIRST valid IP from X-Forwarded-For (client IP, not intermediate proxies)
	assert.Equal(t, "203.0.113.42", ip, "Should use first valid IP from X-Forwarded-For")
}

func TestExtractClientIP_RemoteAddrWithPort_StripPort(t *testing.T) {
	// Should properly handle RemoteAddr with port
	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "203.0.113.10:54321"

	req.Header.Set("X-Forwarded-For", "1.2.3.4")

	config := &pkghttp.IPConfig{
		TrustedProxies: []string{}, // No trusted proxies
	}

	ip := pkghttp.ExtractClientIP(req, config)

	// Should strip port from RemoteAddr
	assert.Equal(t, "203.0.113.10", ip, "Should strip port from RemoteAddr")
}

func TestExtractClientIP_LocalhostBypass_Prevention(t *testing.T) {
	// Verify that attacker cannot bypass rate limiting by claiming to be localhost
	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "203.0.113.10:54321" // Attacker's real IP

	// Attacker tries to claim they're localhost to bypass rate limiting
	req.Header.Set("X-Forwarded-For", "127.0.0.1, 203.0.113.10")

	config := &pkghttp.IPConfig{
		TrustedProxies: []string{"10.0.0.0/8"}, // Only internal network trusted
	}

	ip := pkghttp.ExtractClientIP(req, config)

	// Should ignore X-Forwarded-For because request is not from trusted proxy
	assert.Equal(t, "203.0.113.10", ip, "Should prevent localhost bypass attack")
}
