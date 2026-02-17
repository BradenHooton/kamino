# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Kamino is a Go backend API built with clean architecture principles. It provides a foundation for building scalable REST APIs with JWT authentication, user management, and extensible service layers.

**Tech Stack:**
- **Framework:** Chi v5 (lightweight, composable HTTP middleware)
- **Auth:** JWT (golang-jwt/jwt v5) + bcrypt for password hashing
- **Database:** PostgreSQL with goose migrations
- **Logging:** log/slog (structured logging)
- **Testing:** Go's standard testing package with fixtures for integration tests

**Go Version:** 1.24.5

## Architecture

The codebase follows a layered architecture:

```
cmd/api/main.go                 # Entry point, HTTP server setup, graceful shutdown
├── internal/
│   ├── handlers/               # HTTP request handlers (userHandler, authHandler)
│   ├── services/               # Business logic layer (UserService, AuthService)
│   ├── repositories/           # Data access layer (interfaces + implementations)
│   ├── models/                 # Domain models (User, Auth, error sentinels)
│   ├── auth/                   # Authentication concerns (token, mfa, otp, etc.)
│   ├── middleware/             # Chi middleware (auth checks, rate limiting)
│   ├── routes/                 # Route registration
│   ├── database/               # DB connection, connection pooling
│   └── config/                 # Configuration loading
├── pkg/                        # Shared utilities (errors, logger, validators)
├── migrations/                 # Goose SQL migrations
└── tests/                      # Fixtures and integration tests

```

### Dependency Flow

Handlers receive interface-based dependencies (UserService, etc.). Services depend on repository interfaces for data access. This decoupling makes testing easier and allows swapping implementations.

**Example flow for GET /users/{id}:**
1. HTTP request → UserHandler.GetUser()
2. Handler calls UserService.GetUserByID()
3. Service calls UserRepository.GetByID()
4. Repository queries PostgreSQL
5. Models returned up the chain, converted to UserResponse DTO

## Common Commands

**Build:**
```bash
go build -o kamino ./cmd/api
```

**Run:**
```bash
go run ./cmd/api/main.go
```

**Tests:**
```bash
go test ./...                    # Run all tests
go test -v ./internal/services   # Run tests in a specific package
go test -run TestUserService ./internal/services  # Run specific test
```

**Database Migrations:**
```bash
goose postgres "postgres://user:pass@localhost/kamino" status
goose postgres "postgres://user:pass@localhost/kamino" up
```

**Linting (if configured):**
```bash
golangci-lint run ./...
```

## Key Patterns

### 1. Interface-Based Dependencies
Services and handlers accept interfaces, not concrete types. This enables:
- Easy mocking in tests
- Swappable implementations (e.g., in-memory vs. PostgreSQL repositories)

Example:
```go
type UserService struct {
    repo UserRepository  // Interface, not concrete type
}

type UserRepository interface {
    GetByID(ctx context.Context, id string) (*User, error)
    // ...
}
```

### 2. Error Handling
Use sentinel errors defined in `internal/models/error.go`:
- `ErrNotFound` → HTTP 404
- `ErrConflict` → HTTP 409
- `ErrUnauthorized` → HTTP 401
- `ErrForbidden` → HTTP 403

Check errors with `errors.Is()` in handlers to map to correct HTTP status codes.

### 3. Request/Response DTOs
Handlers define request and response types (e.g., CreateUserRequest, UserResponse). These decouple the HTTP API from domain models, allowing API changes without affecting business logic.

### 4. Context Propagation
Services create `context.Background()` for repository calls. As the project grows, pass contexts from handlers through the entire call chain for deadline/cancellation support.

### 5. Structured Logging
Use `slog` for logging:
```go
logger.Info("user created", slog.String("user_id", id), slog.String("email", email))
logger.Error("failed to create user", slog.Any("error", err))
```

## Adding Features

**To add a new resource (e.g., Products):**

1. Create model in `internal/models/product.go`
2. Define repository interface in `internal/repositories/product_repo.go`
3. Implement repository in `internal/repositories/product_repo_impl.go` (or similar)
4. Create service in `internal/services/product_service.go`
5. Create handler in `internal/handlers/product.go`
6. Register routes in `internal/routes/routes.go`
7. Add database migration in `migrations/XXX_create_products.sql`
8. Wire dependencies in `cmd/api/main.go`

**To add authentication/authorization:**
- Implement middleware in `internal/middleware/` (e.g., auth.go)
- Use Chi's middleware chaining: `r.With(authMiddleware).Post("/users", handler)`
- Check `internal/auth/` for existing JWT/token utilities

## Testing Notes

- Integration tests live in `tests/integration/`
- Test fixtures in `tests/fixtures/`
- Use interfaces for mocking repository calls in service tests
- For DB-dependent tests, consider using test fixtures or embedded databases

## Configuration

Currently minimal. As the project grows:
- Environment variables loaded via `godotenv` or similar
- Configuration file support via `viper` (already in go.mod)
- Separate dev/staging/production configs

Check `internal/config/` for existing setup.

## Notes for Future Work

- Database connection pooling and query timeouts need implementation
- Validation logic in handlers (validate request struct) is a placeholder—integrate go-playground/validator or similar
- Consider adding structured request/response logging middleware
- Rate limiting middleware should be added before going to production
