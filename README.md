# beebase-auth-service

Authentication service for [BeeBase](https://github.com/sbezhuk?tab=repositories&q=beebase),
an open-source backend for a beekeeper management application split into
microservices. See [CLAUDE.md](CLAUDE.md) for the architectural rules this
service follows.

This is one of several BeeBase services:

| Service | Repo | Owns |
|---|---|---|
| **auth-service** (this repo) | `beebase-auth-service` | users, refresh tokens, JWT issuing |
| apiary-service | `beebase-apiary-service` | apiaries |
| hive-service | `beebase-hive-service` | hives |
| inspection-service | `beebase-inspection-service` | inspections |
| gateway | `beebase-gateway` | single entry point, routes to the above |

`beebase-common` ([repo](https://github.com/sbezhuk/beebase-common)) is a
shared Go module every service depends on: structured logging, JSON
response/error helpers, graceful shutdown, and access-token verification.

## Trust model

This service holds the **only** private key in the whole deployment and is
the only one that can mint access tokens (register/login/refresh). Every
other service verifies tokens against this service's public key, fetched
live from `/.well-known/jwks.json`, and can never forge one — see
[Authentication](#authentication) below.

## Requirements

- Go 1.27+
- PostgreSQL 16 (or Docker, to run it for you)
- [golang-migrate](https://github.com/golang-migrate/migrate) CLI, for applying
  migrations outside Docker: `make migrate-install`

## Quick start

```bash
cp .env.example .env
make keygen                          # prints a JWT_PRIVATE_KEY line — paste it into .env
openssl rand -base64 32              # prints a TOTP_ENCRYPTION_KEY value — paste it into .env

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
curl http://localhost:8080/.well-known/jwks.json   # this service's public key

curl -X POST http://localhost:8080/api/v1/auth/register \
  -H 'Content-Type: application/json' \
  -d '{"email":"you@example.com","password":"supersecret"}'
# -> {"status":"totp_setup_required","setup_token":"...","otpauth_uri":"otpauth://...","secret":"...","expires_at":...}
# Scan otpauth_uri (or enter secret manually) in Google Authenticator, then:
curl -X POST http://localhost:8080/api/v1/auth/2fa/setup/verify \
  -H 'Content-Type: application/json' \
  -d '{"setup_token":"<from above>","otp":"<6-digit code>"}'
# -> a full session (access_token in the body, refresh_token as an HttpOnly cookie)
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
| `JWT_PRIVATE_KEY`           | *(required)*                 | Base64-encoded Ed25519 private key (`make keygen`) |
| `ACCESS_TOKEN_TTL`          | `15m`                        | Access token lifetime                      |
| `REFRESH_TOKEN_TTL`         | `720h` (30 days)             | Refresh token lifetime                     |
| `MEDIA_SERVICE_URL`         | *(required)*                 | media-service's base URL, used to verify ownership of a profile's avatar |
| `TOTP_ENCRYPTION_KEY`       | *(required)*                 | Base64-encoded 32-byte AES-256 key encrypting TOTP secrets at rest (`openssl rand -base64 32`) |
| `TOTP_ISSUER`               | `BeeBase`                    | Label shown in a user's authenticator app |
| `TOTP_SETUP_TOKEN_TTL`      | `15m`                        | How long a pending 2FA setup challenge stays valid |
| `LOGIN_CHALLENGE_TTL`       | `5m`                         | How long a pending login OTP challenge stays valid |
| `PASSWORD_RESET_FLOW_TTL`   | `10m`                        | How long a forgot-password flow stays valid overall |
| `PASSWORD_RESET_TOKEN_TTL`  | `10m`                        | How long the post-OTP-verify reset token stays valid |
| `TOTP_MAX_FAILED_ATTEMPTS`  | `5`                          | Failed OTP attempts (login/setup/change-password) before an account-level lockout |
| `TOTP_LOCKOUT_DURATION`     | `15m`                        | How long an account-level OTP lockout lasts |
| `PASSWORD_RESET_FLOW_MAX_OTP_ATTEMPTS` | `5`               | Failed OTP attempts on a single forgot-password flow before that flow is dead |
| `TEST_DATABASE_URL`         | *(unset)*                    | Used only by `make test-integration`, never by the app |

`JWT_PRIVATE_KEY` must stay **identical across every replica** of this
service — every replica issues and verifies against the same key, and other
services all fetch the same JWKS document, so a per-replica key would make
tokens fail to verify depending on which replica issued them.

## Project structure

```
cmd/
  server/                    entry point: wires config, logger, db, services, server
  keygen/                     generates a new JWT_PRIVATE_KEY
api/openapi.yaml               API contract
migrations/                    SQL migrations (golang-migrate format)
internal/
  domain/                       entities + repository ports; no infrastructure dependency
    user/                         User entity, Repository port
    token/                        RefreshToken entity, Repository port
    totp/                         TOTP Credential entity (2FA enrollment), Repository port
    loginchallenge/                LoginChallenge entity (login OTP gate), Repository port
    passwordreset/                 PasswordResetFlow entity, Repository port
  application/                   use cases; depend only on domain ports
    auth/                          register, login, refresh, logout, current user, update profile,
                                     2FA setup/verify, change password, forgot-password flow
  repository/postgres/           domain ports implemented against PostgreSQL (pgx, explicit SQL)
  platform/
    postgres/                      pgx connection pool
    password/                       bcrypt password hashing
    jwtauth/                        EdDSA access-token issuing + key management
    tokenhash/                      opaque refresh/challenge/flow token generation + hashing
    totp/                           RFC 6238 TOTP generation + validation (Google Authenticator)
    totpsecret/                     AES-256-GCM encryption for TOTP secrets at rest
    mediaclient/                    media-service client (verifies avatar ownership)
  transport/http/                 chi router, health/ready/JWKS handlers
    auth/                           auth HTTP handlers, request validation, responses
    profile/                        profile HTTP handlers, request validation, responses
```

logger, httpx (response/error helpers), the graceful-shutdown server
wrapper, and access-token *verification* + its middleware all live in
[beebase-common](https://github.com/sbezhuk/beebase-common) instead, since
every other BeeBase service needs them too.

Package layout follows the dependency direction described in
[CLAUDE.md](CLAUDE.md): HTTP/infrastructure depends inward on application,
which depends inward on domain. Domain packages import nothing from this
project outside `domain/`. HTTP handlers never touch a repository directly —
they only call into an application service.

## Authentication

- Passwords are hashed with bcrypt; refresh tokens are opaque random
  values, stored only as a SHA-256 hash.
- Access tokens are **EdDSA-signed JWTs**. This service holds the only
  private key (`JWT_PRIVATE_KEY`) and is the only one that can mint a
  token. Every other BeeBase service verifies tokens against the matching
  public key, fetched from this service's `GET /.well-known/jwks.json` and
  cached/refreshed automatically (`beebase-common/authmw`) — none of them
  can forge a token, only check one.
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

## Two-factor authentication (TOTP)

Google Authenticator-compatible TOTP (RFC 6238) is required to complete
registration, to log in, to change a password, and to recover a forgotten
one. Credentials alone are never sufficient for any of these.

- **Register** creates the account and returns a setup challenge (an
  `otpauth://` URI and raw secret) — not a session. `POST
  /auth/2fa/setup/verify` with the returned `setup_token` and a valid code
  completes setup and issues the first session.
- **Login** never issues a session directly: on valid credentials it
  returns either an OTP challenge (`POST /auth/login/verify-otp` to
  finish) if 2FA is already enabled, or a fresh setup challenge if it
  isn't — an account that starts registration but never finishes 2FA
  setup can always resume this way, gated on knowing the current password.
- **Change password** (`POST /auth/change-password`, authenticated)
  requires the current password *and* a valid OTP together; either check
  failing leaves the password untouched.
- **Forgot password** is entirely OTP-gated: `POST
  /auth/password-reset/request` (email) → `POST
  /auth/password-reset/verify-otp` (flow token + OTP) → `POST
  /auth/password-reset/confirm` (reset token + new password). The
  request step always responds identically whether or not the email
  belongs to an eligible account, so it can't be used to enumerate
  registered emails. Confirming resets the password and revokes every
  existing refresh token for the account.
- TOTP secrets are encrypted at rest (AES-256-GCM, `TOTP_ENCRYPTION_KEY`)
  and never returned by any endpoint after the one-time setup response.
- OTP brute-force protection is two separate budgets, deliberately never
  shared: an **account-level** lockout (`TOTP_MAX_FAILED_ATTEMPTS` /
  `TOTP_LOCKOUT_DURATION`) for flows that already prove password knowledge
  (login, setup, change-password), and a **flow-scoped** cap
  (`PASSWORD_RESET_FLOW_MAX_OTP_ATTEMPTS`) for a single forgot-password
  attempt — an unauthenticated caller guessing against a reset flow can
  never lock the real account out of logging in.

## Development

```bash
make run               # go run ./cmd/server
make keygen             # generate a new JWT_PRIVATE_KEY
make fmt                # go fmt ./...
make vet                # go vet ./...
make test               # unit tests: go test ./...
make lint               # golangci-lint run

make migrate-up         # apply migrations to DATABASE_URL
make migrate-down       # roll back the last migration
make migrate-new name=add_something   # scaffold a new migration pair

make build              # build binary into bin/
```

### Integration tests

Integration tests exercise the PostgreSQL repositories and the full HTTP
auth flow (register → login → refresh → logout → me, plus a live JWKS
round trip) against a real database. They're gated on `TEST_DATABASE_URL`
and skip themselves (not fail) if it's unset, and every test runs inside a
transaction that's rolled back afterward, so they never leave rows behind
or need manual cleanup.

```bash
docker compose up -d postgres
createdb -h localhost -U beebase beebase_test   # or: docker compose exec postgres createdb -U beebase beebase_test
migrate -path migrations -database "$TEST_DATABASE_URL" up

TEST_DATABASE_URL=postgres://beebase:beebase@localhost:5432/beebase_test?sslmode=disable \
  make test-integration
```
