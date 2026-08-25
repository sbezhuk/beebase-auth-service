// Command server is the entry point for the BeeBase backend.
package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/joho/godotenv"

	appauth "github.com/sbezhuk/BeeBase-Server/internal/application/auth"
	"github.com/sbezhuk/BeeBase-Server/internal/config"
	"github.com/sbezhuk/BeeBase-Server/internal/platform/jwtauth"
	"github.com/sbezhuk/BeeBase-Server/internal/platform/logger"
	"github.com/sbezhuk/BeeBase-Server/internal/platform/password"
	"github.com/sbezhuk/BeeBase-Server/internal/platform/postgres"
	repopostgres "github.com/sbezhuk/BeeBase-Server/internal/repository/postgres"
	"github.com/sbezhuk/BeeBase-Server/internal/server"
	authhttp "github.com/sbezhuk/BeeBase-Server/internal/transport/http/auth"

	transporthttp "github.com/sbezhuk/BeeBase-Server/internal/transport/http"
)

func main() {
	if err := run(); err != nil {
		slog.Error("server exited with error", "error", err)
		os.Exit(1)
	}
}

func run() error {
	// .env is optional: present in local dev, absent in production/containers.
	_ = godotenv.Load()

	cfg, err := config.Load()
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}

	log := logger.New(cfg.Env, cfg.LogLevel)
	slog.SetDefault(log)

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	connectCtx, cancelConnect := context.WithTimeout(ctx, cfg.DatabaseConnectTimeout)
	db, err := postgres.New(connectCtx, cfg.DatabaseURL)
	cancelConnect()
	if err != nil {
		return fmt.Errorf("connect to database: %w", err)
	}
	defer db.Close()

	log.Info("connected to database")

	userRepo := repopostgres.NewUserRepository(db)
	refreshTokenRepo := repopostgres.NewRefreshTokenRepository(db)
	hasher := password.NewBcryptHasher(0)
	tokenIssuer := jwtauth.NewIssuer(cfg.JWTSecret, cfg.AccessTokenTTL)

	authService := appauth.NewService(userRepo, refreshTokenRepo, hasher, tokenIssuer, cfg.RefreshTokenTTL)
	authHandler := authhttp.NewHandler(authService, log)

	router := transporthttp.NewRouter(log, db, authHandler, tokenIssuer)

	srv := server.New(server.Config{
		Addr:         ":" + cfg.HTTPPort,
		Handler:      router,
		ReadTimeout:  cfg.HTTPReadTimeout,
		WriteTimeout: cfg.HTTPWriteTimeout,
		IdleTimeout:  cfg.HTTPIdleTimeout,
	})

	errCh := make(chan error, 1)
	go func() {
		log.Info("starting http server", "port", cfg.HTTPPort, "env", cfg.Env)
		errCh <- srv.Run()
	}()

	select {
	case err := <-errCh:
		if err != nil {
			return fmt.Errorf("run server: %w", err)
		}
		return nil
	case <-ctx.Done():
		log.Info("shutdown signal received")
	}

	shutdownCtx, cancelShutdown := context.WithTimeout(context.Background(), cfg.HTTPShutdownTimeout)
	defer cancelShutdown()

	if err := srv.Shutdown(shutdownCtx); err != nil {
		return fmt.Errorf("graceful shutdown: %w", err)
	}

	log.Info("server stopped cleanly")
	return nil
}
