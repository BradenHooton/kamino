---
name: backend-engineer
description: Expert Go backend engineer skill. Use this skill when building or maintaining Go backend services using idiomatic practices and the specified tech stack (Chi, Goose, Postgres, pgx, Asynq, slog, Testify). Triggers on tasks like setting up Go projects, adding HTTP endpoints, implementing business logic, database migrations, and background jobs.
---

# Backend Engineer

This skill equips Claude with the expertise of a senior Go backend engineer, specializing in building scalable, testable, and maintainable services.

## Core Expertise

- **Language**: Idiomatic Go & Effective Go practices.
- **Web Framework**: Chi for routing and middleware.
- **Database**: Postgres with `pgx` (and optionally `sqlc`).
- **Migrations**: Goose for database versioning.
- **Background Jobs**: Asynq for distributed task processing.
- **Logging**: Structured logging with `log/slog`.
- **Testing**: Testify for assertions and Test-containers for integration testing.
- **Validation**: `go-playground/validator` for request validation.

## Strategic Guidelines

- **Accept Interfaces, Return Structs**: Ensure flexibility and ease of testing.
- **Small Interfaces**: Keep abstractions focused and manageable.
- **Dependency Injection**: Avoid global state; wire dependencies in `main.go`.
- **Project Structure**: Follow the standard layout defined in [project-structure.md](references/project-structure.md).
- **Implementation Patterns**: Use established patterns for error handling, DI, and logging as detailed in [implementation-patterns.md](references/implementation-patterns.md).

## Workflow Decision Tree

1. **New Project?**
   - Start by initializing the project structure. See [project-structure.md](references/project-structure.md).
   - Use the boilerplate in `assets/go-boilerplate/`.
2. **Adding an Endpoint?**
   - Define the request/response models in `internal/domain`.
   - Implement the handler in `internal/api`.
   - Implement business logic in `internal/service`.
   - Implement data access in `internal/repository`.
3. **Database Changes?**
   - Create a new migration using `goose create`.
   - Update repository methods using `pgx`.
4. **Background Tasks?**
   - Define the task type and payload.
   - Implement the task handler for Asynq.
5. **Testing?**
   - Write unit tests for services using mocks.
   - Write integration tests for repositories using Test-containers.

## Resources

- [Project Structure Reference](references/project-structure.md): Standard directory layout.
- [Implementation Patterns](references/implementation-patterns.md): idiomatic Go coding standards.
- [Tech Stack Usage](references/tech-stack.md): Specific library guidance.
- [Boilerplate Asset](assets/go-boilerplate/): Starting point for new services.
