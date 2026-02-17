package database

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/BradenHooton/kamino/internal/config"
	"github.com/jackc/pgx/v5/pgxpool"
)

type DB struct {
	Pool   *pgxpool.Pool
	logger *slog.Logger
}

func NewConnection(cfg *config.DatabaseConfig, logger *slog.Logger) (*DB, error) {
	poolConfig, err := pgxpool.ParseConfig(cfg.DSN())
	if err != nil {
		return nil, fmt.Errorf("unable to parse database config: %w", err)
	}

	// Configure connection pool
	poolConfig.MaxConns = cfg.MaxConns
	poolConfig.MinConns = cfg.MinConns
	poolConfig.MaxConnLifetime = cfg.MaxConnLifetime
	poolConfig.MaxConnIdleTime = cfg.MaxConnIdleTime
	poolConfig.HealthCheckPeriod = cfg.HealthCheckPeriod

	// Create connection pool with timeout
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	pool, err := pgxpool.NewWithConfig(ctx, poolConfig)
	if err != nil {
		return nil, fmt.Errorf("unable to create connection pool: %w", err)
	}

	// Verify connection
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("unable to ping database: %w", err)
	}

	logger.Info("database connection established",
		slog.Int("max_conns", int(cfg.MaxConns)),
		slog.Int("min_conns", int(cfg.MinConns)),
	)

	return &DB{Pool: pool, logger: logger}, nil
}

func (db *DB) Close() {
	db.logger.Info("closing database connection pool")
	db.Pool.Close()
}

func (db *DB) HealthCheck(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()

	if err := db.Pool.Ping(ctx); err != nil {
		return fmt.Errorf("database health check failed: %w", err)
	}
	return nil
}

func (db *DB) Stats() *pgxpool.Stat {
	return db.Pool.Stat()
}
