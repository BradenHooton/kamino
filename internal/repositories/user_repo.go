package repositories

import (
	"context"
	"fmt"
	"time"

	"github.com/BradenHooton/kamino/internal/database"
	"github.com/BradenHooton/kamino/internal/models"
	"github.com/BradenHooton/kamino/pkg/auth"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type UserRepository struct {
	pool *pgxpool.Pool
}

func NewUserRepository(db *database.DB) *UserRepository {
	return &UserRepository{pool: db.Pool}
}

// rowScanner interface for scanning user rows (supports both single row and multiple rows)
type rowScanner interface {
	Scan(dest ...interface{}) error
}

// scanUserRow handles nullable fields and populates a User model from a database row
func scanUserRow(scanner rowScanner) (*models.User, error) {
	var user models.User
	var passwordHash *string
	var lockedUntil, passwordChangedAt *time.Time

	err := scanner.Scan(
		&user.ID, &user.Email, &passwordHash, &user.Name,
		&user.EmailVerified, &user.TokenKey, &user.Role, &user.Status,
		&lockedUntil, &passwordChangedAt,
		&user.CreatedAt, &user.UpdatedAt,
	)
	if err != nil {
		return nil, database.MapPostgresError(err)
	}

	if passwordHash != nil {
		user.PasswordHash = *passwordHash
	}
	user.LockedUntil = lockedUntil
	user.PasswordChangedAt = passwordChangedAt

	return &user, nil
}

// scanUserRows iterates through rows and scans each into User models
func scanUserRows(rows pgx.Rows) ([]*models.User, error) {
	defer rows.Close()

	users := make([]*models.User, 0)

	for rows.Next() {
		user, err := scanUserRow(rows)
		if err != nil {
			return nil, fmt.Errorf("failed to scan user: %w", err)
		}
		users = append(users, user)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating rows: %w", err)
	}

	return users, nil
}

func (r *UserRepository) GetByID(ctx context.Context, id string) (*models.User, error) {
	query := `
		SELECT id, email, password_hash, name, email_verified, token_key, role, status, locked_until, password_changed_at, created_at, updated_at
		FROM users WHERE id = $1
	`

	user, err := scanUserRow(r.pool.QueryRow(ctx, query, id))
	if err != nil {
		return nil, err
	}

	return user, nil
}

func (r *UserRepository) List(ctx context.Context, limit, offset int) ([]*models.User, error) {
	query := `
		SELECT id, email, password_hash, name, email_verified, token_key, role, status, locked_until, password_changed_at, created_at, updated_at
		FROM users ORDER BY created_at DESC LIMIT $1 OFFSET $2
	`

	rows, err := r.pool.Query(ctx, query, limit, offset)
	if err != nil {
		return nil, fmt.Errorf("failed to query users: %w", err)
	}

	return scanUserRows(rows)
}

func (r *UserRepository) Create(ctx context.Context, user *models.User) (*models.User, error) {
	user.ID = uuid.New().String()

	tokenKey, err := auth.GenerateTokenKey()
	if err != nil {
		return nil, fmt.Errorf("failed to generate token key: %w", err)
	}
	user.TokenKey = tokenKey

	now := time.Now()
	user.CreatedAt = now
	user.UpdatedAt = now

	if user.Role == "" {
		user.Role = "user"
	}

	if user.Status == "" {
		user.Status = "active"
	}

	query := `
		INSERT INTO users (id, email, password_hash, name, email_verified, token_key, role, status, password_changed_at, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
		RETURNING id, email, password_hash, name, email_verified, token_key, role, status, locked_until, password_changed_at, created_at, updated_at
	`

	var passwordHash *string
	if user.PasswordHash != "" {
		passwordHash = &user.PasswordHash
	}

	createdUser, err := scanUserRow(r.pool.QueryRow(ctx, query,
		user.ID, user.Email, passwordHash, user.Name,
		user.EmailVerified, user.TokenKey, user.Role, user.Status,
		user.PasswordChangedAt, user.CreatedAt, user.UpdatedAt,
	))

	if err != nil {
		return nil, err
	}

	return createdUser, nil
}

func (r *UserRepository) Update(ctx context.Context, id string, user *models.User) (*models.User, error) {
	user.UpdatedAt = time.Now()

	query := `
		UPDATE users SET name = $1, role = $2, status = $3, token_key = $4, locked_until = $5, email_verified = $6, updated_at = $7
		WHERE id = $8
		RETURNING id, email, password_hash, name, email_verified, token_key, role, status, locked_until, password_changed_at, created_at, updated_at
	`

	updatedUser, err := scanUserRow(r.pool.QueryRow(ctx, query,
		user.Name, user.Role, user.Status, user.TokenKey, user.LockedUntil, user.EmailVerified, user.UpdatedAt, id,
	))

	if err != nil {
		return nil, err
	}

	return updatedUser, nil
}

func (r *UserRepository) Delete(ctx context.Context, id string) error {
	query := `DELETE FROM users WHERE id = $1`

	result, err := r.pool.Exec(ctx, query, id)
	if err != nil {
		return database.MapPostgresError(err)
	}

	if result.RowsAffected() == 0 {
		return models.ErrNotFound
	}

	return nil
}

func (r *UserRepository) GetByEmail(ctx context.Context, email string) (*models.User, error) {
	query := `
		SELECT id, email, password_hash, name, email_verified, token_key, role, status, locked_until, password_changed_at, created_at, updated_at
		FROM users WHERE email = $1
	`

	user, err := scanUserRow(r.pool.QueryRow(ctx, query, email))
	if err != nil {
		return nil, err
	}

	return user, nil
}
