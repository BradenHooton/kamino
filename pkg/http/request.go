package http

import (
	"net"
	"net/http"
	"strings"
)

// ExtractClientIP extracts the real client IP address from the request
// It checks in order: X-Forwarded-For, X-Real-IP, RemoteAddr
// This handles proxies/load balancers correctly
func ExtractClientIP(r *http.Request) string {
	// 1. Check X-Forwarded-For (can contain multiple IPs, take the first real one)
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		ips := strings.Split(xff, ",")
		for _, ip := range ips {
			ip = strings.TrimSpace(ip)
			if isValidIP(ip) {
				return ip
			}
		}
	}

	// 2. Check X-Real-IP
	if xri := r.Header.Get("X-Real-IP"); xri != "" {
		if isValidIP(xri) {
			return xri
		}
	}

	// 3. Fall back to RemoteAddr
	if r.RemoteAddr != "" {
		// RemoteAddr may include port: "ip:port"
		if ip, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
			return ip
		}
		// If no port, just use it directly
		return r.RemoteAddr
	}

	return "unknown"
}

// isValidIP checks if a string is a valid IPv4 or IPv6 address
func isValidIP(ip string) bool {
	return net.ParseIP(ip) != nil
}
