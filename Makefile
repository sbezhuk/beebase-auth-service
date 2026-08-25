.PHONY: run build fmt vet test lint tidy docker-up docker-down docker-build docker-logs

APP_NAME := server
BIN_DIR  := bin

run: ## Run the server locally (loads .env).
	go run ./cmd/server

build: ## Build the server binary into bin/.
	CGO_ENABLED=0 go build -o $(BIN_DIR)/$(APP_NAME) ./cmd/server

fmt: ## Format all Go source.
	go fmt ./...

vet: ## Run go vet on all packages.
	go vet ./...

test: ## Run the test suite.
	go test ./... -v

lint: ## Run golangci-lint, if installed.
	golangci-lint run

tidy: ## Sync go.mod/go.sum with imports.
	go mod tidy

docker-up: ## Start postgres + app via docker-compose.
	docker compose up --build

docker-down: ## Stop and remove docker-compose services.
	docker compose down

docker-build: ## Build the app image only.
	docker compose build app

docker-logs: ## Tail app logs.
	docker compose logs -f app
