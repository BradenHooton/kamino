package models

import (
	"testing"
)

func TestNewAPIKeyUsageMetadata_Complete(t *testing.T) {
	endpoint := "/users/123"
	method := "GET"
	requiredScopes := []string{"users.read"}
	statusCode := 200
	keyPrefix := "kmn_abc12345"
	ipAddress := "192.168.1.1"
	userAgent := "curl/7.68.0"

	metadata := NewAPIKeyUsageMetadata(endpoint, method, requiredScopes, statusCode, keyPrefix, &ipAddress, &userAgent)

	// Verify all fields populated correctly
	if metadata["endpoint"] != endpoint {
		t.Errorf("expected endpoint %s, got %v", endpoint, metadata["endpoint"])
	}
	if metadata["method"] != method {
		t.Errorf("expected method %s, got %v", method, metadata["method"])
	}
	if metadata["status_code"] != statusCode {
		t.Errorf("expected status_code %d, got %v", statusCode, metadata["status_code"])
	}
	if metadata["key_prefix"] != keyPrefix {
		t.Errorf("expected key_prefix %s, got %v", keyPrefix, metadata["key_prefix"])
	}

	// Verify scopes array
	scopes, ok := metadata["required_scopes"].([]string)
	if !ok {
		t.Errorf("expected required_scopes to be []string, got %T", metadata["required_scopes"])
	}
	if len(scopes) != 1 || scopes[0] != "users.read" {
		t.Errorf("expected required_scopes to be [users.read], got %v", scopes)
	}

	// Verify IP and user agent included when provided
	if metadata["ip_address"] != ipAddress {
		t.Errorf("expected ip_address %s, got %v", ipAddress, metadata["ip_address"])
	}
	if metadata["user_agent"] != userAgent {
		t.Errorf("expected user_agent %s, got %v", userAgent, metadata["user_agent"])
	}
}

func TestNewAPIKeyUsageMetadata_OmitOptionalFields(t *testing.T) {
	endpoint := "/api-keys"
	method := "POST"
	requiredScopes := []string{"api_keys.create"}
	statusCode := 403
	keyPrefix := "kmn_xyz67890"

	metadata := NewAPIKeyUsageMetadata(endpoint, method, requiredScopes, statusCode, keyPrefix, nil, nil)

	// Verify required fields present
	if metadata["endpoint"] != endpoint {
		t.Errorf("expected endpoint %s, got %v", endpoint, metadata["endpoint"])
	}
	if metadata["status_code"] != statusCode {
		t.Errorf("expected status_code %d, got %v", statusCode, metadata["status_code"])
	}

	// Verify optional fields omitted when nil
	if _, hasIP := metadata["ip_address"]; hasIP {
		t.Errorf("expected ip_address to be omitted when nil, but found: %v", metadata["ip_address"])
	}
	if _, hasUA := metadata["user_agent"]; hasUA {
		t.Errorf("expected user_agent to be omitted when nil, but found: %v", metadata["user_agent"])
	}
}
