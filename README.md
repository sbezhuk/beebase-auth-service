# BeeBase Server

Open-source backend for a beekeeper management application. See
[CLAUDE.md](CLAUDE.md) for the architectural rules this project follows.

This repository currently contains the **project foundation** (configuration,
HTTP server, PostgreSQL connection, structured logging, graceful shutdown,
health/readiness endpoints) and the **authentication module** (register,
login, refresh-token rotation, logout, current user). Apiaries, hives, and
inspections are not implemented yet.

## Requirements

- Go 1.27+
- PostgreSQL 16 (or Docker, to run it for you)
- [golang-migrate](https://github.com/golang-migrate/migrate) CLI, for applying
  migrations outside Docker: `make migrate-install`

## Quick start

```bash
cp .env.example .env
# then edit .env and set a real JWT_SECRET, e.g.:
#   sed -i '' "s/^JWT_SECRET=.*/JWT_SECRET=$(openssl rand -base64 32)/" .env

# Option A: run Postgres in Docker, app on the host
docker compose up -d postgres
make migrate-up
make run

# Option B: run everything in Docker (migrations run once, automatically)
docker compose up --build
```

Verify it's up:

```bash
curl http://localhost:8080/health   # liveness — always 200 while the process is up
curl http://localhost:8080/ready    # readiness — 200 only if the database is reachable

curl -X POST http://localhost:8080/api/v1/auth/register \
  -H 'Content-Type: application/json' \
  -d '{"email":"you@example.com","password":"supersecret"}'
```

The full API surface is documented in [api/openapi.yaml](api/openapi.yaml).

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
| `JWT_SECRET`                | *(required)*                 | Symmetric secret used to sign access tokens |
| `ACCESS_TOKEN_TTL`          | `15m`                        | Access token lifetime                      |
| `REFRESH_TOKEN_TTL`         | `720h` (30 days)             | Refresh token lifetime                     |
| `TEST_DATABASE_URL`         | *(unset)*                    | Used only by `make test-integration`, never by the app |

## Project structure

```
cmd/server/               entry point: wires config, logger, db, services, server
api/openapi.yaml           API contract
migrations/                 SQL migrations (golang-migrate format)
internal/
  domain/                    entities + repository ports; no infrastructure dependency
    user/                      User entity, Repository port
    token/                     RefreshToken entity, Repository port
  application/                use cases; depend only on domain ports
    auth/                       register, login, refresh, logout, current user
  repository/postgres/        domain ports implemented against PostgreSQL (pgx, explicit SQL)
  platform/
    logger/                     slog setup
    postgres/                   pgx connection pool
    password/                    bcrypt password hashing
    jwtauth/                     JWT access token issuing/verification
    tokenhash/                   opaque refresh token generation + hashing
  server/                      http.Server wrapper with graceful shutdown
  transport/http/              chi router, middleware, health/ready handlers
    auth/                        auth HTTP handlers, request validation, responses
    middleware/                  access-token authentication middleware
    httpx/                       shared JSON response/error helpers
```

Package layout follows the dependency direction described in
[CLAUDE.md](CLAUDE.md): HTTP/infrastructure depends inward on application,
which depends inward on domain. Domain packages import nothing from this
project outside `domain/`. HTTP handlers never touch a repository directly —
they only call into an application service.

## Authentication

- Passwords are hashed with bcrypt; access tokens are HS256 JWTs signed with
  `JWT_SECRET`; refresh tokens are opaque random values, stored only as a
  SHA-256 hash.
- Every successful `/auth/refresh` **rotates** the refresh token: the
  presented token is revoked and a new one is issued. Presenting a token
  that was already revoked is treated as evidence of theft and revokes
  every refresh token for that user, ending the whole session family.
- `/auth/logout` is idempotent — revoking an already-revoked or unknown
  token still returns `204`.
- Login and refresh failures return the same generic error regardless of
  cause (unknown email vs. wrong password; expired vs. revoked vs. unknown
  token), so a client can't use error responses to enumerate accounts or
  probe token state.

## Development

```bash
make run               # go run ./cmd/server
make fmt               # go fmt ./...
make vet               # go vet ./...
make test              # unit tests: go test ./...
make lint              # golangci-lint run

make migrate-up        # apply migrations to DATABASE_URL
make migrate-down       # roll back the last migration
make migrate-new name=add_apiaries_table   # scaffold a new migration pair

make build              # build binary into bin/
```

### Integration tests

Integration tests exercise the PostgreSQL repositories and the full HTTP
auth flow (register → login → refresh → logout → me) against a real
database. They're gated on `TEST_DATABASE_URL` and skip themselves (not
fail) if it's unset, and every test runs inside a transaction that's rolled
back afterward, so they never leave rows behind or need manual cleanup.

```bash
docker compose up -d postgres
createdb -h localhost -U beebase beebase_test   # or: docker compose exec postgres createdb -U beebase beebase_test
migrate -path migrations -database "$TEST_DATABASE_URL" up

TEST_DATABASE_URL=postgres://beebase:beebase@localhost:5432/beebase_test?sslmode=disable \
  make test-integration
```
