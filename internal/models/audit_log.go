package models

import (
	"database/sql/driver"
	"encoding/json"
	"time"

	"github.com/google/uuid"
)

// Event types for audit logging
const (
	AuditEventTypeLogin         = "login"
	AuditEventTypeLogout        = "logout"
	AuditEventTypeRegister      = "register"
	AuditEventTypeRoleChange    = "role_change"
	AuditEventTypeMFASetup      = "mfa_setup"
	AuditEventTypeMFADisable    = "mfa_disable"
	AuditEventTypeAPIKeyOp      = "api_key_operation"
	AuditEventTypeAPIKeyUsage   = "api_key_usage"
	AuditEventTypeMFARecovery   = "mfa_recovery"
	AuditEventTypeUserSuspended = "user_suspended"
	AuditEventTypeUserActivated = "user_activated"
	AuditEventTypeUserLocked    = "user_locked"
)

// Resource types
const (
	AuditResourceTypeUser       = "user"
	AuditResourceTypeAPIKey     = "api_key"
	AuditResourceTypePermission = "permission"
)

// Actions
const (
	AuditActionCreate = "create"
	AuditActionUpdate = "update"
	AuditActionDelete = "delete"
	AuditActionAccess = "access"
)

type AuditLog struct {
	ID            uuid.UUID     `db:"id"`
	EventType     string        `db:"event_type"`
	ActorID       *uuid.UUID    `db:"actor_id"`
	TargetID      *uuid.UUID    `db:"target_id"`
	ResourceType  *string       `db:"resource_type"`
	ResourceID    *string       `db:"resource_id"`
	Action        string        `db:"action"`
	Success       bool          `db:"success"`
	FailureReason *string       `db:"failure_reason"`
	IPAddress     *string       `db:"ip_address"`
	UserAgent     *string       `db:"user_agent"`
	Metadata      AuditMetadata `db:"metadata"`
	CreatedAt     time.Time     `db:"created_at"`
}

// AuditMetadata holds additional context for audit events
type AuditMetadata map[string]interface{}

// Scan implements sql.Scanner for JSONB
func (am *AuditMetadata) Scan(value interface{}) error {
	if value == nil {
		*am = make(AuditMetadata)
		return nil
	}

	bytes, ok := value.([]byte)
	if !ok {
		return ErrBadRequest
	}

	var m map[string]interface{}
	if err := json.Unmarshal(bytes, &m); err != nil {
		return err
	}
	*am = AuditMetadata(m)
	return nil
}

// Value implements driver.Valuer for JSONB
func (am AuditMetadata) Value() (driver.Value, error) {
	if am == nil {
		return nil, nil
	}
	return json.Marshal(am)
}

// MarshalJSON implements json.Marshaler
func (am AuditMetadata) MarshalJSON() ([]byte, error) {
	return json.Marshal(map[string]interface{}(am))
}

// UnmarshalJSON implements json.Unmarshaler
func (am *AuditMetadata) UnmarshalJSON(data []byte) error {
	var m map[string]interface{}
	if err := json.Unmarshal(data, &m); err != nil {
		return err
	}
	*am = AuditMetadata(m)
	return nil
}

// NewAPIKeyUsageMetadata creates metadata for API key usage audit events
func NewAPIKeyUsageMetadata(endpoint, method string, requiredScopes []string, statusCode int, keyPrefix string, ipAddress, userAgent *string) AuditMetadata {
	metadata := AuditMetadata{
		"endpoint":        endpoint,
		"method":          method,
		"required_scopes": requiredScopes,
		"status_code":     statusCode,
		"key_prefix":      keyPrefix,
	}
	if ipAddress != nil {
		metadata["ip_address"] = *ipAddress
	}
	if userAgent != nil {
		metadata["user_agent"] = *userAgent
	}
	return metadata
}
