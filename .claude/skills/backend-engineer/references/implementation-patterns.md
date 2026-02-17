# Go Implementation Patterns

Follow these trusted patterns and strategies for high-quality, testable Go code.

## 1. Accept Interfaces, Return Structs

This is a fundamental Go proverb. It allows the caller to mock dependencies easily while providing the caller with the concrete type it needs.

```go
// Good: Service accepts a repository interface
type Service struct {
    repo domain.UserRepository
}

func NewService(repo domain.UserRepository) *Service {
    return &Service{repo: repo}
}
```

## 2. Small Interfaces

Keep interfaces small and focused (the "Interface Segregation Principle"). It's better to have multiple small interfaces than one large "God" interface.

```go
// Good: Small, focused interfaces
type Reader interface {
    Read(p []byte) (n int, err error)
}

type Writer interface {
    Write(p []byte) (n int, err error)
}
```

## 3. Dependency Injection (DI)

Explicitly pass dependencies into constructors (`New...` functions). Avoid global state or `init()` functions for dependency setup.

## 4. Error Handling

- **Wrap Errors**: Use `fmt.Errorf("context: %w", err)` to provide context while preserving the original error.
- **Sentinel Errors**: Define custom error types for expected failure conditions that the caller might need to check (e.g., `ErrNotFound`).
- **Handle Once**: Log errors at the top level (handlers or main), not deep in the library code.

## 5. Functional Options

Use functional options for configuration when a constructor has many optional parameters.

```go
type Server struct {
    port int
}

type Option func(*Server)

func WithPort(port int) Option {
    return func(s *Server) {
        s.port = port
    }
}

func NewServer(opts ...Option) *Server {
    s := &Server{port: 8080}
    for _, opt := range opts {
        opt(s)
    }
    return s
}
```

## 6. Functional Logging with slog

Use `log/slog` for structured logging. Pass the `context.Context` to loggers and include relevant attributes.

```go
logger.InfoContext(ctx, "user created", slog.String("user_id", user.ID))
```
