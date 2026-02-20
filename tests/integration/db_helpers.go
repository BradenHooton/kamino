package integration

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log"
	"path/filepath"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jackc/pgx/v5/stdlib"
	"github.com/pressly/goose/v3"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/modules/postgres"
	"github.com/testcontainers/testcontainers-go/wait"

	"github.com/BradenHooton/kamino/internal/database"
	"github.com/BradenHooton/kamino/internal/models"
	"github.com/BradenHooton/kamino/internal/repositories"
	"github.com/BradenHooton/kamino/pkg/auth"
)

// TestDB manages PostgreSQL testcontainer and database operations
type TestDB struct {
	Container  testcontainers.Container
	ConnString string
	Pool       *pgxpool.Pool
	DB         *database.DB
}

// SetupTestDatabase creates a PostgreSQL testcontainer, runs migrations, returns TestDB
func SetupTestDatabase(ctx context.Context) (*TestDB, error) {
	// Create PostgreSQL container
	container, err := postgres.RunContainer(ctx,
		testcontainers.WithImage("postgres:16-alpine"),
		postgres.WithInitScripts(),
		postgres.WithDatabase("kamino"),
		postgres.WithUsername("postgres"),
		postgres.WithPassword("postgres"),
		testcontainers.WithWaitStrategy(
			wait.ForLog("database system is ready to accept connections").
				WithOccurrence(2).
				WithStartupTimeout(30*1000),
		),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to start postgres container: %w", err)
	}

	// Get connection string
	connStr, err := container.ConnectionString(ctx, "sslmode=disable")
	if err != nil {
		container.Terminate(ctx)
		return nil, fmt.Errorf("failed to get connection string: %w", err)
	}

	// Create connection pool
	pool, err := pgxpool.New(ctx, connStr)
	if err != nil {
		container.Terminate(ctx)
		return nil, fmt.Errorf("failed to create connection pool: %w", err)
	}

	// Test connection
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		container.Terminate(ctx)
		return nil, fmt.Errorf("failed to ping database: %w", err)
	}

	// Run migrations
	if err := runMigrations(ctx, pool); err != nil {
		pool.Close()
		container.Terminate(ctx)
		return nil, fmt.Errorf("failed to run migrations: %w", err)
	}

	// Create database.DB wrapper
	dbWrapper := &database.DB{
		Pool: pool,
	}

	return &TestDB{
		Container:  container,
		ConnString: connStr,
		Pool:       pool,
		DB:         dbWrapper,
	}, nil
}

// runMigrations executes all goose migrations
func runMigrations(ctx context.Context, pool *pgxpool.Pool) error {
	// Get absolute path to migrations directory
	migrationsDir, err := filepath.Abs("../../migrations")
	if err != nil {
		return fmt.Errorf("failed to get migrations path: %w", err)
	}

	// Suppress goose logs
	goose.SetLogger(log.New(nil, "", 0))

	// Goose needs stdlib DB connection
	// Use stdlib adapter from pgx
	sqlDB := stdlib.OpenDB(*pool.Config().ConnConfig)
	defer sqlDB.Close()

	// Run migrations on the stdlib DB
	if err := goose.UpContext(ctx, sqlDB, migrationsDir); err != nil {
		return fmt.Errorf("migration failed: %w", err)
	}

	return nil
}

// Teardown stops the container and closes the connection pool
func (db *TestDB) Teardown(ctx context.Context) error {
	if db.Pool != nil {
		db.Pool.Close()
	}
	if db.Container != nil {
		return db.Container.Terminate(ctx)
	}
	return nil
}

// CleanupTables truncates all tables for test isolation
func (db *TestDB) CleanupTables(ctx context.Context) error {
	tables := []string{
		"mfa_attempts",
		"mfa_devices",
		"email_verification_tokens",
		"login_attempts",
		"revoked_tokens",
		"csrf_tokens",
		"users",
	}

	for _, table := range tables {
		if _, err := db.Pool.Exec(ctx, fmt.Sprintf("TRUNCATE TABLE %s CASCADE", table)); err != nil {
			return fmt.Errorf("failed to truncate table %s: %w", table, err)
		}
	}

	return nil
}

// InitializeRepositories creates all repository instances from database wrapper
func InitializeRepositories(db *database.DB) (
	*repositories.UserRepository,
	*repositories.TokenRevocationRepository,
	*repositories.LoginAttemptRepository,
	*repositories.EmailVerificationRepository,
	repositories.MFADeviceRepository,
	repositories.MFAAttemptRepository,
) {
	return repositories.NewUserRepository(db),
		repositories.NewTokenRevocationRepository(db),
		repositories.NewLoginAttemptRepository(db),
		repositories.NewEmailVerificationRepository(db),
		repositories.NewMFADeviceRepository(db.Pool),
		repositories.NewMFAAttemptRepository(db.Pool)
}

// SeedUser inserts a test user with hashed password
func SeedUser(ctx context.Context, pool *pgxpool.Pool, email, password string, verified bool) (*models.User, error) {
	// Hash password
	hashedPassword, err := auth.HashPassword(password)
	if err != nil {
		return nil, fmt.Errorf("failed to hash password: %w", err)
	}

	// Insert user
	query := `
		INSERT INTO users (email, password_hash, email_verified, created_at, updated_at)
		VALUES ($1, $2, $3, NOW(), NOW())
		RETURNING id, email, password_hash, email_verified, mfa_enabled, role, created_at, updated_at
	`

	var user models.User
	err = pool.QueryRow(ctx, query, email, hashedPassword, verified).Scan(
		&user.ID,
		&user.Email,
		&user.PasswordHash,
		&user.EmailVerified,
		&user.MFAEnabled,
		&user.Role,
		&user.CreatedAt,
		&user.UpdatedAt,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to insert user: %w", err)
	}

	return &user, nil
}

// sha256Hash computes SHA256 hash of input string
func sha256Hash(input string) string {
	hash := sha256.Sum256([]byte(input))
	return hex.EncodeToString(hash[:])
}

// SeedEmailVerificationToken creates a verification token for user
func SeedEmailVerificationToken(ctx context.Context, pool *pgxpool.Pool, userID string) (string, error) {
	// Generate token and hash
	token := "test-verification-token-" + userID
	tokenHash := sha256Hash(token)

	query := `
		INSERT INTO email_verification_tokens (user_id, token_hash, used, created_at, expires_at)
		VALUES ($1, $2, false, NOW(), NOW() + INTERVAL '24 hours')
		RETURNING user_id
	`

	var returnedUserID string
	err := pool.QueryRow(ctx, query, userID, tokenHash).Scan(&returnedUserID)
	if err != nil {
		return "", fmt.Errorf("failed to insert verification token: %w", err)
	}

	return token, nil
}

// SeedMFADevice creates an MFA device for a user
func SeedMFADevice(ctx context.Context, pool *pgxpool.Pool, userID string) (string, error) {
	// Generate encrypted secret
	encryptedSecret := "test-encrypted-secret-" + userID
	backupCodes := "code1,code2,code3,code4,code5"

	query := `
		INSERT INTO mfa_devices (user_id, encrypted_secret, backup_codes, created_at, last_used_at)
		VALUES ($1, $2, $3, NOW(), NOW())
		RETURNING encrypted_secret
	`

	var secret string
	err := pool.QueryRow(ctx, query, userID, encryptedSecret, backupCodes).Scan(&secret)
	if err != nil {
		return "", fmt.Errorf("failed to insert MFA device: %w", err)
	}

	return secret, nil
}

// SeedExpiredEmailVerificationToken creates an expired verification token (>24hrs old)
func SeedExpiredEmailVerificationToken(ctx context.Context, pool *pgxpool.Pool, userID string) (string, error) {
	// Generate token and hash
	token := "test-expired-token-" + userID
	tokenHash := sha256Hash(token)

	query := `
		INSERT INTO email_verification_tokens (user_id, token_hash, used, created_at, expires_at)
		VALUES ($1, $2, false, NOW() - INTERVAL '25 hours', NOW() - INTERVAL '1 hour')
		RETURNING user_id
	`

	var returnedUserID string
	err := pool.QueryRow(ctx, query, userID, tokenHash).Scan(&returnedUserID)
	if err != nil {
		return "", fmt.Errorf("failed to insert expired token: %w", err)
	}

	return token, nil
}
