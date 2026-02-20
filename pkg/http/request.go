package http

import (
	"net"
	"net/http"
	"strings"
)

// IPConfig holds configuration for IP extraction and validation
type IPConfig struct {
	TrustedProxies []string // CIDR ranges of trusted proxies
}

// ExtractClientIP extracts the real client IP address from the request
// It validates X-Forwarded-For and X-Real-IP headers only from trusted proxies
// to prevent IP spoofing attacks via header manipulation
//
// Flow:
// 1. If request is from trusted proxy, check X-Forwarded-For header
// 2. If request is from trusted proxy, check X-Real-IP header
// 3. Fall back to RemoteAddr
func ExtractClientIP(r *http.Request, config *IPConfig) string {
	remoteIP := getRemoteAddr(r)

	// Only trust X-Forwarded-For if request comes from trusted proxy
	if config != nil && isTrustedProxy(remoteIP, config.TrustedProxies) {
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
	}

	// 3. Fall back to RemoteAddr
	return remoteIP
}

// getRemoteAddr extracts the IP address from RemoteAddr (removing port if present)
func getRemoteAddr(r *http.Request) string {
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

// isTrustedProxy checks if an IP address is within any of the trusted proxy CIDR ranges
func isTrustedProxy(ip string, trustedProxies []string) bool {
	if len(trustedProxies) == 0 {
		return false
	}

	clientIP := net.ParseIP(ip)
	if clientIP == nil {
		return false
	}

	for _, cidr := range trustedProxies {
		_, ipNet, err := net.ParseCIDR(cidr)
		if err != nil {
			continue // Skip invalid CIDR ranges
		}
		if ipNet.Contains(clientIP) {
			return true
		}
	}

	return false
}

// isValidIP checks if a string is a valid IPv4 or IPv6 address
func isValidIP(ip string) bool {
	return net.ParseIP(ip) != nil
}
