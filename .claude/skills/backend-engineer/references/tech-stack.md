# Tech Stack Usage Guide

Guidelines for using the specific libraries in the backend engineer tech stack.

## Routing: chi

- Use `chi.NewRouter()` for the main router.
- Use `r.Group()` for grouping routes with shared middleware (e.g., auth).
- Keep handlers thin; call service methods.

## Database: postgres & pgx

- Use `pgxpool` for connection pooling.
- Use `sqlc` if possible (recommended for type safety), or raw SQL with `pgx`.
- Prefer `UUID` for primary keys.

## Migrations: goose

- Store migrations in `/migrations`.
- Use `.sql` files for migrations.
- Run migrations during application startup or via a CLI tool.

## Background Jobs: asynq

- Define tasks as structs with `ProcessTask(context.Context, *asynq.Task) error` methods.
- Use a dedicated worker entry point if the workload is high.

## Testing: testify & test-containers

- Use `stevevc/testify/assert` and `stevevc/testify/require`.
- Use `test-containers-go` for integration tests requiring a real Postgres instance.
- Prefer table-driven tests for unit logic.

## Validation: validator

- Use `github.com/go-playground/validator/v10`.
- Define validation tags on request structs.

```go
type CreateUserRequest struct {
    Email string `validate:"required,email"`
    Age   int    `validate:"gte=18"`
}
```

## Configuration: godotenv

- Load `.env` files in `main.go` using `godotenv.Load()`.
- Use a `config` package to parse environment variables into a struct.
