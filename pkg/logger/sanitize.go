package logger

import (
	"log/slog"
	"strings"
)

// SanitizedEmail masks an email address for logging (e.g., "u***@e***.com")
func SanitizedEmail(email string) string {
	parts := strings.Split(email, "@")
	if len(parts) != 2 {
		return "[invalid-email]"
	}

	username := parts[0]
	domain := parts[1]

	// Mask username: keep first char, mask rest
	if len(username) > 1 {
		username = string(username[0]) + strings.Repeat("*", len(username)-1)
	}

	// Mask domain: keep TLD, mask the rest
	domainParts := strings.Split(domain, ".")
	if len(domainParts) > 1 {
		// Mask all but the TLD
		for i := 0; i < len(domainParts)-1; i++ {
			domainParts[i] = strings.Repeat("*", len(domainParts[i]))
		}
		domain = strings.Join(domainParts, ".")
	}

	return username + "@" + domain
}

// RedactedAttr returns a redacted slog attribute for sensitive values
// In production, returns "[REDACTED]"; in development, returns the actual value
func RedactedAttr(key, value, env string) slog.Attr {
	if env == "production" {
		return slog.String(key, "[REDACTED]")
	}
	return slog.String(key, value)
}

// SanitizeQueryString checks if query string contains sensitive parameters
// and returns true if the entire query string should be redacted
func SanitizeQueryString(rawQuery string) bool {
	sensitiveParams := map[string]bool{
		"password":  true,
		"token":     true,
		"secret":    true,
		"api_key":   true,
		"apikey":    true,
		"email":     true,
		"apitoken":  true,
		"auth":      true,
		"csrf":      true,
	}

	query := strings.ToLower(rawQuery)
	for param := range sensitiveParams {
		if strings.Contains(query, param) {
			return true
		}
	}
	return false
}
