# Go Backend Project Structure

Follow this standard directory layout for idiomatic Go backend services.

## Directory Layout

```text
.
├── cmd/
│   └── server/
│       └── main.go       # Entry point for the HTTP server
├── internal/             # Private application and library code
│   ├── api/              # HTTP handlers and routing (Chi)
│   ├── config/           # Configuration management (Godotenv, slog)
│   ├── domain/           # Domain models and interface definitions
│   ├── repository/       # Data access layer (Postgres, pgx)
│   ├── service/          # Business logic layer
│   └── worker/           # Background jobs (Asynq)
├── migrations/           # SQL migration files (Goose)
├── pkg/                  # Public library code (use sparingly)
├── scripts/              # Build and development scripts
├── tests/                # Integration tests (Test-containers)
├── .env.example          # Example environment variables
├── docker-compose.yml    # Local development infrastructure
├── go.mod                # Go module definition
└── go.sum                # Go module checksums
```

## Key Principles

- **internal/**: Code that should not be imported by other modules. Most logic lives here.
- **cmd/**: Small main functions that wire up dependencies and start the application.
- **domain/**: Contains the core models and interfaces. This package should have minimal dependencies.
- **Thin Handlers**: Handlers in `internal/api` should only handle HTTP concerns and delegate to services.
- **Service Layer**: Business logic lives in `internal/service`. Services depend on repository interfaces.
- **Repository Layer**: Data access logic lives in `internal/repository`. It implements interfaces defined in `domain` or `service`.
