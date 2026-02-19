package repositories

import (
	"context"
	"fmt"
	"time"

	"github.com/BradenHooton/kamino/internal/database"
	"github.com/BradenHooton/kamino/internal/models"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// EmailVerificationRepository handles email verification token data access
type EmailVerificationRepository struct {
	pool *pgxpool.Pool
}

// NewEmailVerificationRepository creates a new EmailVerificationRepository
func NewEmailVerificationRepository(db *database.DB) *EmailVerificationRepository {
	return &EmailVerificationRepository{pool: db.Pool}
}

// scanTokenRow handles nullable fields and populates an EmailVerificationToken model from a database row
func scanTokenRow(row rowScanner) (*models.EmailVerificationToken, error) {
	var token models.EmailVerificationToken
	var usedAt *time.Time

	err := row.Scan(
		&token.ID, &token.UserID, &token.TokenHash, &token.Email,
		&token.ExpiresAt, &usedAt, &token.CreatedAt,
	)
	if err != nil {
		return nil, database.MapPostgresError(err)
	}

	token.UsedAt = usedAt
	return &token, nil
}

// scanTokenRows iterates through rows and scans each into EmailVerificationToken models
func scanTokenRows(rows pgx.Rows) ([]*models.EmailVerificationToken, error) {
	defer rows.Close()

	tokens := make([]*models.EmailVerificationToken, 0)

	for rows.Next() {
		token, err := scanTokenRow(rows)
		if err != nil {
			return nil, fmt.Errorf("failed to scan email verification token: %w", err)
		}
		tokens = append(tokens, token)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating token rows: %w", err)
	}

	return tokens, nil
}

// Create creates a new email verification token
func (r *EmailVerificationRepository) Create(ctx context.Context, userID, tokenHash, email string, expiresAt time.Time) (*models.EmailVerificationToken, error) {
	query := `
		INSERT INTO email_verification_tokens (user_id, token_hash, email, expires_at)
		VALUES ($1, $2, $3, $4)
		RETURNING id, user_id, token_hash, email, expires_at, used_at, created_at
	`

	token, err := scanTokenRow(r.pool.QueryRow(ctx, query, userID, tokenHash, email, expiresAt))
	if err != nil {
		return nil, fmt.Errorf("failed to create email verification token: %w", err)
	}

	return token, nil
}

// GetByTokenHash retrieves a token by its hash
func (r *EmailVerificationRepository) GetByTokenHash(ctx context.Context, tokenHash string) (*models.EmailVerificationToken, error) {
	query := `
		SELECT id, user_id, token_hash, email, expires_at, used_at, created_at
		FROM email_verification_tokens
		WHERE token_hash = $1
	`

	token, err := scanTokenRow(r.pool.QueryRow(ctx, query, tokenHash))
	if err != nil {
		return nil, err
	}

	return token, nil
}

// MarkAsUsed marks a token as used
func (r *EmailVerificationRepository) MarkAsUsed(ctx context.Context, id string) error {
	query := `
		UPDATE email_verification_tokens
		SET used_at = NOW()
		WHERE id = $1 AND used_at IS NULL
	`

	result, err := r.pool.Exec(ctx, query, id)
	if err != nil {
		return fmt.Errorf("failed to mark token as used: %w", err)
	}

	if result.RowsAffected() == 0 {
		return models.ErrNotFound
	}

	return nil
}

// DeleteByUserID deletes all tokens for a user
func (r *EmailVerificationRepository) DeleteByUserID(ctx context.Context, userID string) error {
	query := `DELETE FROM email_verification_tokens WHERE user_id = $1`

	_, err := r.pool.Exec(ctx, query, userID)
	if err != nil {
		return fmt.Errorf("failed to delete tokens for user: %w", err)
	}

	return nil
}

// CleanupExpired deletes expired tokens older than the threshold
func (r *EmailVerificationRepository) CleanupExpired(ctx context.Context) (int64, error) {
	query := `
		DELETE FROM email_verification_tokens
		WHERE expires_at < NOW() - INTERVAL '30 days'
	`

	result, err := r.pool.Exec(ctx, query)
	if err != nil {
		return 0, fmt.Errorf("failed to cleanup expired tokens: %w", err)
	}

	return result.RowsAffected(), nil
}

// GetPendingByEmail gets the most recent pending (unused) token for an email
func (r *EmailVerificationRepository) GetPendingByEmail(ctx context.Context, email string) (*models.EmailVerificationToken, error) {
	query := `
		SELECT id, user_id, token_hash, email, expires_at, used_at, created_at
		FROM email_verification_tokens
		WHERE email = $1 AND used_at IS NULL AND expires_at > NOW()
		ORDER BY created_at DESC
		LIMIT 1
	`

	token, err := scanTokenRow(r.pool.QueryRow(ctx, query, email))
	if err != nil {
		return nil, err
	}

	return token, nil
}
