package logger

import (
	"context"
	"log/slog"
	"time"
)

// AuditEvent represents a security audit event
type AuditEvent struct {
	EventType     string
	UserID        string
	IPAddress     string
	UserAgent     string
	Success       bool
	FailureReason string
	Metadata      map[string]string
}

// AuditLogger provides audit logging functionality
type AuditLogger struct {
	logger *slog.Logger
}

// NewAuditLogger creates a new audit logger
func NewAuditLogger(logger *slog.Logger) *AuditLogger {
	return &AuditLogger{
		logger: logger,
	}
}

// LogAuthAttempt logs authentication attempts
func (al *AuditLogger) LogAuthAttempt(event AuditEvent) {
	attrs := []slog.Attr{
		slog.String("audit_type", "auth"),
		slog.String("event_type", event.EventType),
		slog.Bool("success", event.Success),
		slog.String("timestamp", time.Now().UTC().Format(time.RFC3339)),
	}

	if event.UserID != "" {
		attrs = append(attrs, slog.String("user_id", event.UserID))
	}
	if event.IPAddress != "" {
		attrs = append(attrs, slog.String("ip_address", event.IPAddress))
	}
	if event.UserAgent != "" {
		attrs = append(attrs, slog.String("user_agent", event.UserAgent))
	}
	if event.FailureReason != "" {
		attrs = append(attrs, slog.String("failure_reason", event.FailureReason))
	}

	if event.Success {
		al.logger.LogAttrs(context.Background(), slog.LevelInfo, "audit", attrs...)
	} else {
		al.logger.LogAttrs(context.Background(), slog.LevelWarn, "audit", attrs...)
	}
}

// LogPasswordChange logs password change events
func (al *AuditLogger) LogPasswordChange(userID, ipAddress string, success bool) {
	attrs := []slog.Attr{
		slog.String("audit_type", "password"),
		slog.String("event_type", "password_change"),
		slog.Bool("success", success),
		slog.String("user_id", userID),
		slog.String("timestamp", time.Now().UTC().Format(time.RFC3339)),
	}

	if ipAddress != "" {
		attrs = append(attrs, slog.String("ip_address", ipAddress))
	}

	if success {
		al.logger.LogAttrs(context.Background(), slog.LevelInfo, "audit", attrs...)
	} else {
		al.logger.LogAttrs(context.Background(), slog.LevelWarn, "audit", attrs...)
	}
}

// LogAccountAction logs general account actions
func (al *AuditLogger) LogAccountAction(eventType, userID, ipAddress string, metadata map[string]string) {
	attrs := []slog.Attr{
		slog.String("audit_type", "account"),
		slog.String("event_type", eventType),
		slog.String("user_id", userID),
		slog.String("timestamp", time.Now().UTC().Format(time.RFC3339)),
	}

	if ipAddress != "" {
		attrs = append(attrs, slog.String("ip_address", ipAddress))
	}

	for key, val := range metadata {
		attrs = append(attrs, slog.String(key, val))
	}

	al.logger.LogAttrs(context.Background(), slog.LevelInfo, "audit", attrs...)
}
