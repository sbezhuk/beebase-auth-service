// Command server is the entry point for the BeeBase auth-service.
package main

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	"github.com/google/uuid"
	"github.com/joho/godotenv"

	appauth "github.com/sbezhuk/beebase-auth-service/internal/application/auth"
	"github.com/sbezhuk/beebase-auth-service/internal/config"
	"github.com/sbezhuk/beebase-auth-service/internal/platform/apiaryclient"
	"github.com/sbezhuk/beebase-auth-service/internal/platform/deletionclient"
	"github.com/sbezhuk/beebase-auth-service/internal/platform/jwtauth"
	"github.com/sbezhuk/beebase-auth-service/internal/platform/mediaclient"
	"github.com/sbezhuk/beebase-auth-service/internal/platform/password"
	"github.com/sbezhuk/beebase-auth-service/internal/platform/postgres"
	"github.com/sbezhuk/beebase-auth-service/internal/platform/totpsecret"
	repopostgres "github.com/sbezhuk/beebase-auth-service/internal/repository/postgres"
	authhttp "github.com/sbezhuk/beebase-auth-service/internal/transport/http/auth"
	profilehttp "github.com/sbezhuk/beebase-auth-service/internal/transport/http/profile"

	"github.com/sbezhuk/beebase-common/authmw"
	"github.com/sbezhuk/beebase-common/httpx"
	"github.com/sbezhuk/beebase-common/jwks"
	"github.com/sbezhuk/beebase-common/logger"
	"github.com/sbezhuk/beebase-common/server"
	"github.com/sbezhuk/beebase-common/sessionstore"

	transporthttp "github.com/sbezhuk/beebase-auth-service/internal/transport/http"
)

type sessionCleanupRequester struct {
	deletion     *repopostgres.DeletionStore
	notification *deletionclient.Client
}

func (c sessionCleanupRequester) RequestDeletion(ctx context.Context, userID uuid.UUID) error {
	return c.deletion.RequestDeletion(ctx, userID)
}

func (c sessionCleanupRequester) DeleteSessionData(ctx context.Context, userID, sessionID uuid.UUID) error {
	return c.notification.DeleteSessionData(ctx, userID, sessionID)
}

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

	redisConnectCtx, cancelRedisConnect := context.WithTimeout(ctx, cfg.RedisConnectTimeout)
	redisClient, err := sessionstore.NewRedisClient(redisConnectCtx, cfg.RedisAddr)
	cancelRedisConnect()
	if err != nil {
		return fmt.Errorf("connect to redis: %w", err)
	}
	defer redisClient.Close()

	log.Info("connected to redis")

	sessions := sessionstore.NewStore(redisClient)

	privateKey, err := jwtauth.ParsePrivateKey(cfg.JWTPrivateKey)
	if err != nil {
		return fmt.Errorf("load JWT private key: %w", err)
	}
	publicKey := privateKey.Public().(ed25519.PublicKey)
	kid := jwtauth.KeyID(publicKey)

	jwksHandler, err := jwks.NewHandler(publicKey, kid)
	if err != nil {
		return fmt.Errorf("build JWKS handler: %w", err)
	}

	totpKey, err := base64.StdEncoding.DecodeString(cfg.TOTPEncryptionKey)
	if err != nil {
		return fmt.Errorf("decode TOTP_ENCRYPTION_KEY: %w", err)
	}
	totpCipher, err := totpsecret.NewCipher(totpKey)
	if err != nil {
		return fmt.Errorf("build totp cipher: %w", err)
	}

	userRepo := repopostgres.NewUserRepository(db)
	refreshTokenRepo := repopostgres.NewRefreshTokenRepository(db)
	credentialRepo := repopostgres.NewTwoFactorCredentialRepository(db)
	loginChallengeRepo := repopostgres.NewLoginChallengeRepository(db)
	passwordResetFlowRepo := repopostgres.NewPasswordResetFlowRepository(db)
	hasher := password.NewBcryptHasher(0)
	tokenIssuer := jwtauth.NewIssuer(privateKey, kid, cfg.AccessTokenTTL)
	mediaClient := mediaclient.New(cfg.MediaServiceURL)
	apiaryClient := apiaryclient.New(cfg.ApiaryServiceURL)

	// auth-service verifies its own tokens (for /auth/me) directly against
	// the public key it already holds in memory, with no JWKS round trip -
	// unlike every other service, which fetches this over HTTP.
	tokenVerifier := authmw.NewVerifierFromPublicKey(publicKey, sessions)

	security := appauth.SecurityConfig{
		RefreshTTL:              cfg.RefreshTokenTTL,
		SetupTokenTTL:           cfg.TOTPSetupTokenTTL,
		LoginChallengeTTL:       cfg.LoginChallengeTTL,
		PasswordResetFlowTTL:    cfg.PasswordResetFlowTTL,
		PasswordResetTokenTTL:   cfg.PasswordResetTokenTTL,
		OTPMaxAttempts:          cfg.TOTPMaxFailedAttempts,
		OTPLockoutDuration:      cfg.TOTPLockoutDuration,
		ResetFlowMaxOTPAttempts: cfg.PasswordResetFlowMaxOTPAttempts,
		TOTPIssuer:              cfg.TOTPIssuer,
	}

	deletionStore := repopostgres.NewDeletionStore(db)
	notificationCleanup := deletionclient.New(cfg.NotificationServiceURL, cfg.InternalServiceToken)
	authService := appauth.NewService(
		userRepo, refreshTokenRepo, credentialRepo, loginChallengeRepo, passwordResetFlowRepo,
		hasher, tokenIssuer, sessions, mediaClient, apiaryClient, totpCipher, security, log,
		sessionCleanupRequester{deletion: deletionStore, notification: notificationCleanup},
	)
	jobStore := repopostgres.NewDeletionJobStore(db)
	cleanup := map[string]appauth.AccountCleanupClient{
		"apiary": deletionclient.New(cfg.ApiaryServiceURL, cfg.InternalServiceToken), "hive": deletionclient.New(cfg.HiveServiceURL, cfg.InternalServiceToken), "inspection": deletionclient.New(cfg.InspectionServiceURL, cfg.InternalServiceToken), "harvest": deletionclient.New(cfg.HarvestServiceURL, cfg.InternalServiceToken), "media": deletionclient.New(cfg.MediaServiceURL, cfg.InternalServiceToken), "notification": notificationCleanup, "subscription": deletionclient.New(cfg.SubscriptionServiceURL, cfg.InternalServiceToken),
	}
	worker := appauth.NewDeletionWorker(jobStore, userRepo, cleanup, log)
	go worker.Run(ctx, cfg.DeletionWorkerInterval)

	cookieOpts := httpx.CookieOptions{
		Domain:   cfg.CookieDomain,
		Secure:   cfg.CookieSecure,
		SameSite: http.SameSiteLaxMode,
	}
	authHandler := authhttp.NewHandler(authService, log, cookieOpts)
	profileHandler := profilehttp.NewHandler(authService, log)

	router := transporthttp.NewRouter(log, db, authHandler, profileHandler, tokenVerifier, jwksHandler)

	srv := server.New(server.Config{
		Addr:         ":" + cfg.HTTPPort,
		Handler:      router,
		ReadTimeout:  cfg.HTTPReadTimeout,
		WriteTimeout: cfg.HTTPWriteTimeout,
		IdleTimeout:  cfg.HTTPIdleTimeout,
	})

	errCh := make(chan error, 1)
	go func() {
		log.Info("starting http server", "port", cfg.HTTPPort, "env", cfg.Env, "jwt_kid", kid)
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
