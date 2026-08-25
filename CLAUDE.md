# BeeBase Server

BeeBase is an open-source backend for a beekeeper management application.

## Architecture

Use pragmatic Clean Architecture / Hexagonal Architecture.

Dependency direction:

HTTP / Infrastructure
        ↓
Application
        ↓
Domain

## Rules

- Use idiomatic Go.
- Keep the domain independent from infrastructure.
- Use Chi for HTTP.
- Use PostgreSQL + pgx.
- Use explicit SQL.
- Do not use an ORM.
- Use UUIDs.
- Use context.Context.
- Use slog for logging.
- Use JWT access tokens.
- Use opaque refresh tokens.
- Hash refresh tokens before storing them.
- Never store passwords in plaintext.
- Never log passwords or tokens.
- Keep HTTP handlers thin.
- Business logic belongs in application/domain layers.
- Do not access repositories directly from HTTP handlers.
- Do not introduce generic repositories.
- Avoid unnecessary abstractions.
- Avoid global mutable state.
- Keep the application stateless.
- The backend must be horizontally scalable.

## Current MVP

Authentication:
- Register
- Login
- Refresh
- Logout
- Current user

Apiaries:
- CRUD

Hives:
- CRUD

Inspections:
- Create
- Get
- List

## Future

The Flutter client will support offline-first behavior.

The backend must eventually support synchronization.

Synchronizable entities should use:
- UUID
- created_at
- updated_at
- deleted_at

Do not implement full synchronization yet.

## Testing

Before considering a task complete:

go fmt ./...
go vet ./...
go test ./...

If golangci-lint is configured:

golangci-lint run

## Git

Use conventional commits:

feat:
fix:
refactor:
test:
chore:
docs: