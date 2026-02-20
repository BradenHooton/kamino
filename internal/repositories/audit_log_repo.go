package repositories

import (
	"context"
	"fmt"

	"github.com/BradenHooton/kamino/internal/database"
	"github.com/BradenHooton/kamino/internal/models"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// AuditLogRepository handles audit log data access
type AuditLogRepository struct {
	pool *pgxpool.Pool
}

// NewAuditLogRepository creates a new AuditLogRepository
func NewAuditLogRepository(db *database.DB) *AuditLogRepository {
	return &AuditLogRepository{pool: db.Pool}
}

// scanAuditLogRow handles nullable fields and populates an AuditLog model from a database row
func scanAuditLogRow(row rowScanner) (*models.AuditLog, error) {
	var log models.AuditLog

	err := row.Scan(
		&log.ID, &log.EventType, &log.ActorID, &log.TargetID,
		&log.ResourceType, &log.ResourceID, &log.Action, &log.Success,
		&log.FailureReason, &log.IPAddress, &log.UserAgent, &log.Metadata,
		&log.CreatedAt,
	)
	if err != nil {
		return nil, database.MapPostgresError(err)
	}

	return &log, nil
}

// scanAuditLogRows iterates through rows and scans each into AuditLog models
func scanAuditLogRows(rows pgx.Rows) ([]*models.AuditLog, error) {
	defer rows.Close()

	logs := make([]*models.AuditLog, 0)

	for rows.Next() {
		log, err := scanAuditLogRow(rows)
		if err != nil {
			return nil, fmt.Errorf("failed to scan audit log: %w", err)
		}
		logs = append(logs, log)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating audit log rows: %w", err)
	}

	return logs, nil
}

// Create creates a new audit log entry
func (r *AuditLogRepository) Create(ctx context.Context, log *models.AuditLog) (*models.AuditLog, error) {
	query := `
		INSERT INTO audit_logs (
			event_type, actor_id, target_id, resource_type, resource_id,
			action, success, failure_reason, ip_address, user_agent, metadata
		)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
		RETURNING id, event_type, actor_id, target_id, resource_type, resource_id,
		          action, success, failure_reason, ip_address, user_agent, metadata, created_at
	`

	result, err := scanAuditLogRow(r.pool.QueryRow(
		ctx, query,
		log.EventType, log.ActorID, log.TargetID, log.ResourceType, log.ResourceID,
		log.Action, log.Success, log.FailureReason, log.IPAddress, log.UserAgent, log.Metadata,
	))
	if err != nil {
		return nil, fmt.Errorf("failed to create audit log: %w", err)
	}

	return result, nil
}

// GetByUserID retrieves all audit logs for a specific user (as actor or target)
func (r *AuditLogRepository) GetByUserID(ctx context.Context, userID uuid.UUID, limit int, offset int) ([]*models.AuditLog, error) {
	query := `
		SELECT id, event_type, actor_id, target_id, resource_type, resource_id,
		       action, success, failure_reason, ip_address, user_agent, metadata, created_at
		FROM audit_logs
		WHERE actor_id = $1 OR target_id = $1
		ORDER BY created_at DESC
		LIMIT $2 OFFSET $3
	`

	rows, err := r.pool.Query(ctx, query, userID, limit, offset)
	if err != nil {
		return nil, fmt.Errorf("failed to query audit logs: %w", err)
	}

	return scanAuditLogRows(rows)
}

// GetByActorID retrieves all audit logs for a specific actor
func (r *AuditLogRepository) GetByActorID(ctx context.Context, actorID uuid.UUID, limit int, offset int) ([]*models.AuditLog, error) {
	query := `
		SELECT id, event_type, actor_id, target_id, resource_type, resource_id,
		       action, success, failure_reason, ip_address, user_agent, metadata, created_at
		FROM audit_logs
		WHERE actor_id = $1
		ORDER BY created_at DESC
		LIMIT $2 OFFSET $3
	`

	rows, err := r.pool.Query(ctx, query, actorID, limit, offset)
	if err != nil {
		return nil, fmt.Errorf("failed to query audit logs: %w", err)
	}

	return scanAuditLogRows(rows)
}

// GetByEventType retrieves audit logs by event type
func (r *AuditLogRepository) GetByEventType(ctx context.Context, eventType string, limit int, offset int) ([]*models.AuditLog, error) {
	query := `
		SELECT id, event_type, actor_id, target_id, resource_type, resource_id,
		       action, success, failure_reason, ip_address, user_agent, metadata, created_at
		FROM audit_logs
		WHERE event_type = $1
		ORDER BY created_at DESC
		LIMIT $2 OFFSET $3
	`

	rows, err := r.pool.Query(ctx, query, eventType, limit, offset)
	if err != nil {
		return nil, fmt.Errorf("failed to query audit logs: %w", err)
	}

	return scanAuditLogRows(rows)
}

// GetFailedAttempts retrieves failed audit events
func (r *AuditLogRepository) GetFailedAttempts(ctx context.Context, limit int, offset int) ([]*models.AuditLog, error) {
	query := `
		SELECT id, event_type, actor_id, target_id, resource_type, resource_id,
		       action, success, failure_reason, ip_address, user_agent, metadata, created_at
		FROM audit_logs
		WHERE success = false
		ORDER BY created_at DESC
		LIMIT $1 OFFSET $2
	`

	rows, err := r.pool.Query(ctx, query, limit, offset)
	if err != nil {
		return nil, fmt.Errorf("failed to query failed audit logs: %w", err)
	}

	return scanAuditLogRows(rows)
}

// Cleanup removes audit logs older than the specified number of days
func (r *AuditLogRepository) Cleanup(ctx context.Context, olderThanDays int) (int64, error) {
	query := `
		DELETE FROM audit_logs
		WHERE created_at < CURRENT_TIMESTAMP - INTERVAL '1 day' * $1
	`

	result, err := r.pool.Exec(ctx, query, olderThanDays)
	if err != nil {
		return 0, fmt.Errorf("failed to cleanup audit logs: %w", err)
	}

	return result.RowsAffected(), nil
}

// CountByUserID counts audit logs for a specific user
func (r *AuditLogRepository) CountByUserID(ctx context.Context, userID uuid.UUID) (int64, error) {
	query := `
		SELECT COUNT(*)
		FROM audit_logs
		WHERE actor_id = $1 OR target_id = $1
	`

	var count int64
	err := r.pool.QueryRow(ctx, query, userID).Scan(&count)
	if err != nil {
		return 0, fmt.Errorf("failed to count audit logs: %w", err)
	}

	return count, nil
}

// GetByAPIKeyID retrieves all API key usage logs for a specific API key
func (r *AuditLogRepository) GetByAPIKeyID(ctx context.Context, keyID string, limit int, offset int) ([]*models.AuditLog, error) {
	query := `
		SELECT id, event_type, actor_id, target_id, resource_type, resource_id,
		       action, success, failure_reason, ip_address, user_agent, metadata, created_at
		FROM audit_logs
		WHERE event_type = $1 AND resource_id = $2
		ORDER BY created_at DESC
		LIMIT $3 OFFSET $4
	`

	rows, err := r.pool.Query(ctx, query, models.AuditEventTypeAPIKeyUsage, keyID, limit, offset)
	if err != nil {
		return nil, fmt.Errorf("failed to query api key usage logs: %w", err)
	}

	return scanAuditLogRows(rows)
}

// CountByAPIKeyID counts API key usage events for a specific API key
func (r *AuditLogRepository) CountByAPIKeyID(ctx context.Context, keyID string) (int64, error) {
	query := `
		SELECT COUNT(*)
		FROM audit_logs
		WHERE event_type = $1 AND resource_id = $2
	`

	var count int64
	err := r.pool.QueryRow(ctx, query, models.AuditEventTypeAPIKeyUsage, keyID).Scan(&count)
	if err != nil {
		return 0, fmt.Errorf("failed to count api key usage logs: %w", err)
	}

	return count, nil
}
