package database

import (
	"context"
	"errors"

	"github.com/BradenHooton/kamino/internal/models"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

func MapPostgresError(err error) error {
	if err == nil {
		return nil
	}

	if errors.Is(err, pgx.ErrNoRows) {
		return models.ErrNotFound
	}

	if pgErr, ok := err.(*pgconn.PgError); ok {
		switch pgErr.Code {
		case "23505": // unique_violation
			return models.ErrConflict
		case "23503": // foreign_key_violation
			return models.ErrBadRequest
		case "23502": // not_null_violation
			return models.ErrBadRequest
		}
	}

	return err
}

func (db *DB) WithTransaction(ctx context.Context, fn func(pgx.Tx) error) error {
	tx, err := db.Pool.Begin(ctx)
	if err != nil {
		return err
	}

	defer func() {
		if p := recover(); p != nil {
			_ = tx.Rollback(ctx)
			panic(p)
		} else if err != nil {
			_ = tx.Rollback(ctx)
		} else {
			err = tx.Commit(ctx)
		}
	}()

	err = fn(tx)
	return err
}
