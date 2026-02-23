package repositories

import (
	"context"
	"fmt"
	"strings"
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

// UpdateStatus updates only the status field for a user.
func (r *UserRepository) UpdateStatus(ctx context.Context, id, status string) error {
	query := `UPDATE users SET status = $1, updated_at = NOW() WHERE id = $2`

	result, err := r.pool.Exec(ctx, query, status, id)
	if err != nil {
		return database.MapPostgresError(err)
	}
	if result.RowsAffected() == 0 {
		return models.ErrNotFound
	}
	return nil
}

// LockAccount sets locked_until; passing nil clears the lock.
func (r *UserRepository) LockAccount(ctx context.Context, id string, lockedUntil *time.Time) error {
	query := `UPDATE users SET locked_until = $1, updated_at = NOW() WHERE id = $2`

	result, err := r.pool.Exec(ctx, query, lockedUntil, id)
	if err != nil {
		return database.MapPostgresError(err)
	}
	if result.RowsAffected() == 0 {
		return models.ErrNotFound
	}
	return nil
}

// Search returns users matching the given criteria plus the total count for pagination.
func (r *UserRepository) Search(ctx context.Context, c models.SearchCriteria) ([]*models.User, int64, error) {
	if c.Limit <= 0 || c.Limit > 100 {
		c.Limit = 20
	}

	conditions := make([]string, 0)
	args := make([]interface{}, 0)
	argIdx := 1

	if c.Email != nil && *c.Email != "" {
		conditions = append(conditions, fmt.Sprintf("email ILIKE $%d", argIdx))
		args = append(args, "%"+*c.Email+"%")
		argIdx++
	}
	if c.Name != nil && *c.Name != "" {
		conditions = append(conditions, fmt.Sprintf("name ILIKE $%d", argIdx))
		args = append(args, "%"+*c.Name+"%")
		argIdx++
	}
	if c.Role != nil && *c.Role != "" {
		conditions = append(conditions, fmt.Sprintf("role = $%d", argIdx))
		args = append(args, *c.Role)
		argIdx++
	}
	if c.Status != nil && *c.Status != "" {
		conditions = append(conditions, fmt.Sprintf("status = $%d", argIdx))
		args = append(args, *c.Status)
		argIdx++
	}

	where := ""
	if len(conditions) > 0 {
		where = "WHERE " + strings.Join(conditions, " AND ")
	}

	// Count query — uses only the filter args
	countQuery := fmt.Sprintf(`SELECT COUNT(*) FROM users %s`, where)
	var total int64
	if err := r.pool.QueryRow(ctx, countQuery, args...).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("failed to count users: %w", err)
	}

	// Data query — append limit and offset
	limitIdx := argIdx
	offsetIdx := argIdx + 1
	dataArgs := append(args, c.Limit, c.Offset)
	dataQuery := fmt.Sprintf(`
		SELECT id, email, password_hash, name, email_verified, token_key, role, status, locked_until, password_changed_at, created_at, updated_at
		FROM users %s ORDER BY created_at DESC LIMIT $%d OFFSET $%d
	`, where, limitIdx, offsetIdx)

	rows, err := r.pool.Query(ctx, dataQuery, dataArgs...)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to search users: %w", err)
	}

	users, err := scanUserRows(rows)
	if err != nil {
		return nil, 0, err
	}

	return users, total, nil
}

// CountTotal returns the total number of users.
func (r *UserRepository) CountTotal(ctx context.Context) (int64, error) {
	var n int64
	return n, r.pool.QueryRow(ctx, `SELECT COUNT(*) FROM users`).Scan(&n)
}

// CountByStatus returns the number of users with the given status.
func (r *UserRepository) CountByStatus(ctx context.Context, status string) (int64, error) {
	var n int64
	return n, r.pool.QueryRow(ctx, `SELECT COUNT(*) FROM users WHERE status = $1`, status).Scan(&n)
}

// CountByRole returns the number of users with the given role.
func (r *UserRepository) CountByRole(ctx context.Context, role string) (int64, error) {
	var n int64
	return n, r.pool.QueryRow(ctx, `SELECT COUNT(*) FROM users WHERE role = $1`, role).Scan(&n)
}

// CountMFAEnabled returns the number of users with MFA enabled.
func (r *UserRepository) CountMFAEnabled(ctx context.Context) (int64, error) {
	var n int64
	return n, r.pool.QueryRow(ctx, `SELECT COUNT(*) FROM users WHERE mfa_enabled = TRUE`).Scan(&n)
}

// CountNewSince returns the number of users created at or after the given time.
func (r *UserRepository) CountNewSince(ctx context.Context, since time.Time) (int64, error) {
	var n int64
	return n, r.pool.QueryRow(ctx, `SELECT COUNT(*) FROM users WHERE created_at >= $1`, since).Scan(&n)
}
