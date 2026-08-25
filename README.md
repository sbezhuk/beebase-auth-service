# BeeBase Server

Open-source backend for a beekeeper management application. See
[CLAUDE.md](CLAUDE.md) for the architectural rules this project follows.

This repository currently contains only the **project foundation**:
configuration, HTTP server, PostgreSQL connection, structured logging,
graceful shutdown, and health/readiness endpoints. Authentication and the
domain features (apiaries, hives, inspections) are not implemented yet.

## Requirements

- Go 1.27+
- PostgreSQL 16 (or Docker, to run it for you)

## Quick start

```bash
cp .env.example .env

# Option A: run Postgres in Docker, app on the host
docker compose up -d postgres
make run

# Option B: run everything in Docker
docker compose up --build
```

Verify it's up:

```bash
curl http://localhost:8080/health   # liveness — always 200 while the process is up
curl http://localhost:8080/ready    # readiness — 200 only if the database is reachable
```

## Configuration

All configuration is via environment variables (see
[.env.example](.env.example)):

| Variable                   | Default                    | Description                              |
| --------------------------- | --------------------------- | ----------------------------------------- |
| `APP_ENV`                  | `development`               | `development` or `production`             |
| `LOG_LEVEL`                 | `info`                       | `debug`, `info`, `warn`, `error`           |
| `HTTP_PORT`                 | `8080`                       | Port the HTTP server listens on           |
| `HTTP_READ_TIMEOUT`         | `5s`                         | Request read timeout                      |
| `HTTP_WRITE_TIMEOUT`        | `10s`                        | Response write timeout                    |
| `HTTP_IDLE_TIMEOUT`         | `60s`                        | Keep-alive idle timeout                   |
| `HTTP_SHUTDOWN_TIMEOUT`     | `15s`                        | Max time to wait for graceful shutdown    |
| `DATABASE_URL`              | *(required)*                 | PostgreSQL DSN                            |
| `DATABASE_CONNECT_TIMEOUT`  | `5s`                         | Timeout for the initial DB connection      |

## Project structure

```
cmd/server/            entry point: wires config, logger, db, server
internal/
  config/               environment-based configuration
  platform/
    logger/              slog setup
    postgres/             pgx connection pool
  server/                 http.Server wrapper with graceful shutdown
  transport/http/         chi router, middleware, health/ready handlers
migrations/             SQL migrations (empty for now)
```

Package layout follows the dependency direction described in
[CLAUDE.md](CLAUDE.md): transport and platform code depends inward on
application/domain code, never the reverse. Those inner layers don't exist
yet — they'll be added alongside authentication and the domain features.

## Development

```bash
make run     # go run ./cmd/server
make fmt     # go fmt ./...
make vet     # go vet ./...
make test    # go test ./...
make build   # build binary into bin/
```
