package models

import (
	"testing"
)

func TestIsValidScope(t *testing.T) {
	tests := []struct {
		name     string
		scope    string
		expected bool
	}{
		{name: "valid users.read", scope: ScopeUsersRead, expected: true},
		{name: "valid users.write", scope: ScopeUsersWrite, expected: true},
		{name: "valid api_keys.read", scope: ScopeAPIKeysRead, expected: true},
		{name: "valid api_keys.create", scope: ScopeAPIKeysCreate, expected: true},
		{name: "valid api_keys.revoke", scope: ScopeAPIKeysRevoke, expected: true},
		{name: "valid users.delete", scope: ScopeUsersDelete, expected: true},
		{name: "valid audit.read", scope: ScopeAuditRead, expected: true},
		{name: "valid wildcard", scope: ScopeAll, expected: true},
		{name: "invalid scope", scope: "invalid.scope", expected: false},
		{name: "invalid format", scope: "read", expected: false},
		{name: "empty scope", scope: "", expected: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := IsValidScope(tt.scope)
			if result != tt.expected {
				t.Errorf("IsValidScope(%q) = %v, want %v", tt.scope, result, tt.expected)
			}
		})
	}
}

func TestIsAdminOnlyScope(t *testing.T) {
	tests := []struct {
		name     string
		scope    string
		expected bool
	}{
		{name: "admin scope users.delete", scope: ScopeUsersDelete, expected: true},
		{name: "admin scope audit.read", scope: ScopeAuditRead, expected: true},
		{name: "admin scope wildcard", scope: ScopeAll, expected: true},
		{name: "user scope users.read", scope: ScopeUsersRead, expected: false},
		{name: "user scope api_keys.create", scope: ScopeAPIKeysCreate, expected: false},
		{name: "invalid scope", scope: "invalid.scope", expected: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := IsAdminOnlyScope(tt.scope)
			if result != tt.expected {
				t.Errorf("IsAdminOnlyScope(%q) = %v, want %v", tt.scope, result, tt.expected)
			}
		})
	}
}

func TestCanUserRequestScope(t *testing.T) {
	tests := []struct {
		name     string
		role     string
		scope    string
		expected bool
	}{
		// Admin can request any scope
		{name: "admin can request users.read", role: "admin", scope: ScopeUsersRead, expected: true},
		{name: "admin can request users.write", role: "admin", scope: ScopeUsersWrite, expected: true},
		{name: "admin can request users.delete", role: "admin", scope: ScopeUsersDelete, expected: true},
		{name: "admin can request audit.read", role: "admin", scope: ScopeAuditRead, expected: true},
		{name: "admin can request wildcard", role: "admin", scope: ScopeAll, expected: true},

		// Regular user can request user scopes but not admin scopes
		{name: "user can request users.read", role: "user", scope: ScopeUsersRead, expected: true},
		{name: "user can request users.write", role: "user", scope: ScopeUsersWrite, expected: true},
		{name: "user can request api_keys.read", role: "user", scope: ScopeAPIKeysRead, expected: true},
		{name: "user can request api_keys.create", role: "user", scope: ScopeAPIKeysCreate, expected: true},
		{name: "user cannot request users.delete", role: "user", scope: ScopeUsersDelete, expected: false},
		{name: "user cannot request audit.read", role: "user", scope: ScopeAuditRead, expected: false},
		{name: "user cannot request wildcard", role: "user", scope: ScopeAll, expected: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := CanUserRequestScope(tt.role, tt.scope)
			if result != tt.expected {
				t.Errorf("CanUserRequestScope(%q, %q) = %v, want %v", tt.role, tt.scope, result, tt.expected)
			}
		})
	}
}

func TestHasScope(t *testing.T) {
	tests := []struct {
		name     string
		scopes   []string
		required string
		expected bool
	}{
		{name: "has exact scope", scopes: []string{ScopeUsersRead}, required: ScopeUsersRead, expected: true},
		{name: "has scope in list", scopes: []string{ScopeUsersRead, ScopeUsersWrite}, required: ScopeUsersWrite, expected: true},
		{name: "does not have scope", scopes: []string{ScopeUsersRead}, required: ScopeUsersWrite, expected: false},
		{name: "wildcard grants all", scopes: []string{ScopeAll}, required: ScopeUsersRead, expected: true},
		{name: "wildcard in list grants scope", scopes: []string{ScopeUsersRead, ScopeAll}, required: ScopeUsersDelete, expected: true},
		{name: "empty scopes", scopes: []string{}, required: ScopeUsersRead, expected: false},
		{name: "nil scopes", scopes: nil, required: ScopeUsersRead, expected: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := HasScope(tt.scopes, tt.required)
			if result != tt.expected {
				t.Errorf("HasScope(%v, %q) = %v, want %v", tt.scopes, tt.required, result, tt.expected)
			}
		})
	}
}

func TestValidateScopes(t *testing.T) {
	tests := []struct {
		name    string
		scopes  []string
		wantErr bool
	}{
		// Valid scopes
		{name: "valid single scope", scopes: []string{ScopeUsersRead}, wantErr: false},
		{name: "valid multiple scopes", scopes: []string{ScopeUsersRead, ScopeUsersWrite}, wantErr: false},
		{name: "valid api key scopes", scopes: []string{ScopeAPIKeysCreate, ScopeAPIKeysRead}, wantErr: false},
		{name: "valid admin scopes", scopes: []string{ScopeUsersDelete}, wantErr: false},
		{name: "valid wildcard scope", scopes: []string{ScopeAll}, wantErr: false},

		// Invalid scopes
		{name: "empty scopes", scopes: []string{}, wantErr: true},
		{name: "invalid scope not in whitelist", scopes: []string{"invalid.scope"}, wantErr: true},
		{name: "invalid format - missing action", scopes: []string{"users"}, wantErr: true},
		{name: "invalid format - invalid action", scopes: []string{"users.invalid"}, wantErr: true},
		{name: "invalid format - extra dots", scopes: []string{"users.read.extra"}, wantErr: true},
		{name: "invalid format - uppercase", scopes: []string{"Users.Read"}, wantErr: true},
		{name: "mix of valid and invalid", scopes: []string{ScopeUsersRead, "invalid.scope"}, wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateScopes(tt.scopes)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateScopes(%v) error = %v, wantErr %v", tt.scopes, err, tt.wantErr)
			}
		})
	}
}
