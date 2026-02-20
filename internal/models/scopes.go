package models

// Scope constants define all valid scopes in the system
const (
	// User scopes
	ScopeUsersRead = "users.read"
	ScopeUsersWrite = "users.write"

	// API Key scopes
	ScopeAPIKeysRead = "api_keys.read"
	ScopeAPIKeysCreate = "api_keys.create"
	ScopeAPIKeysRevoke = "api_keys.revoke"

	// Admin-only scopes
	ScopeUsersDelete = "users.delete"
	ScopeAuditRead = "audit.read"

	// Wildcard scope - grants all permissions (admin only)
	ScopeAll = "*"
)

// AllValidScopes is the whitelist of all allowed scopes
var AllValidScopes = map[string]bool{
	ScopeUsersRead: true,
	ScopeUsersWrite: true,
	ScopeAPIKeysRead: true,
	ScopeAPIKeysCreate: true,
	ScopeAPIKeysRevoke: true,
	ScopeUsersDelete: true,
	ScopeAuditRead: true,
	ScopeAll: true,
}

// AdminOnlyScopes is the set of scopes that require admin role
var AdminOnlyScopes = map[string]bool{
	ScopeUsersDelete: true,
	ScopeAuditRead: true,
	ScopeAll: true,
}

// IsValidScope checks if a scope exists in the whitelist
func IsValidScope(scope string) bool {
	return AllValidScopes[scope]
}

// IsAdminOnlyScope checks if a scope requires admin role
func IsAdminOnlyScope(scope string) bool {
	return AdminOnlyScopes[scope]
}

// CanUserRequestScope checks if a user's role allows them to request a specific scope
func CanUserRequestScope(userRole, scope string) bool {
	// Wildcard - only admins can request wildcard scope
	if scope == ScopeAll {
		return userRole == "admin"
	}

	// Admin-only scopes - only admins can request these
	if AdminOnlyScopes[scope] {
		return userRole == "admin"
	}

	// Regular scopes - both users and admins can request
	return true
}

// HasScope checks if a scopes array contains a required scope
// Handles wildcard "*" for super-admin access
func HasScope(scopes []string, required string) bool {
	for _, scope := range scopes {
		// Wildcard grants all scopes
		if scope == ScopeAll {
			return true
		}
		if scope == required {
			return true
		}
	}
	return false
}
