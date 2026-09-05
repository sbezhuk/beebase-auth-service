// Package config loads BeeBase server configuration from environment
// variables, with sane defaults for local development.
package config

import (
	"fmt"
	"os"
	"strconv"
	"time"
)

// Config holds all runtime configuration for the server.
type Config struct {
	Env string // "development" or "production"

	HTTPPort            string
	HTTPReadTimeout     time.Duration
	HTTPWriteTimeout    time.Duration
	HTTPIdleTimeout     time.Duration
	HTTPShutdownTimeout time.Duration

	DatabaseURL            string
	DatabaseConnectTimeout time.Duration

	LogLevel string // "debug", "info", "warn", "error"

	// JWTPrivateKey is a standard-base64-encoded Ed25519 private key (the
	// 64-byte seed+public form from ed25519.GenerateKey). This is the only
	// key that can mint access tokens; every other BeeBase service verifies
	// them against the matching public key via this service's JWKS endpoint.
	JWTPrivateKey   string
	AccessTokenTTL  time.Duration
	RefreshTokenTTL time.Duration

	// CookieDomain scopes the refresh token cookie; empty means "host only"
	// (the domain the response came from), which is right for local dev.
	// CookieSecure controls the cookie's Secure flag; it defaults to true
	// unless Env is "development", so local HTTP dev keeps working while
	// production never ships the cookie over plaintext.
	CookieDomain string
	CookieSecure bool

	// MediaServiceURL is media-service's base URL. Updating a profile's
	// avatar asks it, once, to verify the caller actually owns the
	// referenced media id before it's persisted. Deleting an account also
	// asks it to sweep up every media item belonging to the caller.
	MediaServiceURL string

	// ApiaryServiceURL is apiary-service's base URL. Deleting an account
	// cascades to every apiary the caller owns (and, transitively, their
	// hives, inspections, and media).
	ApiaryServiceURL string

	// TOTPEncryptionKey is a standard-base64-encoded 32-byte AES-256 key
	// used to encrypt TOTP secrets at rest. Decoding and length validation
	// happen in main.go next to totpsecret.NewCipher, the same way
	// JWTPrivateKey's parsing lives in jwtauth.ParsePrivateKey rather than
	// here.
	TOTPEncryptionKey string
	// TOTPIssuer is the label shown in a user's authenticator app
	// alongside their account name.
	TOTPIssuer string

	TOTPSetupTokenTTL               time.Duration
	LoginChallengeTTL               time.Duration
	PasswordResetFlowTTL            time.Duration
	PasswordResetTokenTTL           time.Duration
	TOTPMaxFailedAttempts           int
	TOTPLockoutDuration             time.Duration
	PasswordResetFlowMaxOTPAttempts int
}

// Load builds a Config from environment variables, falling back to
// defaults suitable for local development where a variable is unset.
func Load() (*Config, error) {
	env := getEnv("APP_ENV", "development")

	cfg := &Config{
		Env: env,

		HTTPPort:            getEnv("HTTP_PORT", "8080"),
		HTTPReadTimeout:     getDuration("HTTP_READ_TIMEOUT", 5*time.Second),
		HTTPWriteTimeout:    getDuration("HTTP_WRITE_TIMEOUT", 10*time.Second),
		HTTPIdleTimeout:     getDuration("HTTP_IDLE_TIMEOUT", 60*time.Second),
		HTTPShutdownTimeout: getDuration("HTTP_SHUTDOWN_TIMEOUT", 15*time.Second),

		DatabaseURL:            getEnv("DATABASE_URL", ""),
		DatabaseConnectTimeout: getDuration("DATABASE_CONNECT_TIMEOUT", 5*time.Second),

		LogLevel: getEnv("LOG_LEVEL", "info"),

		JWTPrivateKey:   getEnv("JWT_PRIVATE_KEY", ""),
		AccessTokenTTL:  getDuration("ACCESS_TOKEN_TTL", 15*time.Minute),
		RefreshTokenTTL: getDuration("REFRESH_TOKEN_TTL", 720*time.Hour),

		CookieDomain: getEnv("COOKIE_DOMAIN", ""),
		CookieSecure: getBool("COOKIE_SECURE", env != "development"),

		MediaServiceURL:  getEnv("MEDIA_SERVICE_URL", ""),
		ApiaryServiceURL: getEnv("APIARY_SERVICE_URL", ""),

		TOTPEncryptionKey: getEnv("TOTP_ENCRYPTION_KEY", ""),
		TOTPIssuer:        getEnv("TOTP_ISSUER", "BeeBase"),

		TOTPSetupTokenTTL:               getDuration("TOTP_SETUP_TOKEN_TTL", 15*time.Minute),
		LoginChallengeTTL:               getDuration("LOGIN_CHALLENGE_TTL", 5*time.Minute),
		PasswordResetFlowTTL:            getDuration("PASSWORD_RESET_FLOW_TTL", 10*time.Minute),
		PasswordResetTokenTTL:           getDuration("PASSWORD_RESET_TOKEN_TTL", 10*time.Minute),
		TOTPMaxFailedAttempts:           getInt("TOTP_MAX_FAILED_ATTEMPTS", 5),
		TOTPLockoutDuration:             getDuration("TOTP_LOCKOUT_DURATION", 15*time.Minute),
		PasswordResetFlowMaxOTPAttempts: getInt("PASSWORD_RESET_FLOW_MAX_OTP_ATTEMPTS", 5),
	}

	if cfg.DatabaseURL == "" {
		return nil, fmt.Errorf("config: DATABASE_URL is required")
	}
	if cfg.JWTPrivateKey == "" {
		return nil, fmt.Errorf("config: JWT_PRIVATE_KEY is required")
	}
	if cfg.MediaServiceURL == "" {
		return nil, fmt.Errorf("config: MEDIA_SERVICE_URL is required")
	}
	if cfg.ApiaryServiceURL == "" {
		return nil, fmt.Errorf("config: APIARY_SERVICE_URL is required")
	}
	if cfg.TOTPEncryptionKey == "" {
		return nil, fmt.Errorf("config: TOTP_ENCRYPTION_KEY is required")
	}

	return cfg, nil
}

func getEnv(key, fallback string) string {
	if v, ok := os.LookupEnv(key); ok && v != "" {
		return v
	}
	return fallback
}

func getDuration(key string, fallback time.Duration) time.Duration {
	v, ok := os.LookupEnv(key)
	if !ok || v == "" {
		return fallback
	}
	d, err := time.ParseDuration(v)
	if err != nil {
		return fallback
	}
	return d
}

func getInt(key string, fallback int) int {
	v, ok := os.LookupEnv(key)
	if !ok || v == "" {
		return fallback
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return fallback
	}
	return n
}

func getBool(key string, fallback bool) bool {
	v, ok := os.LookupEnv(key)
	if !ok || v == "" {
		return fallback
	}
	b, err := strconv.ParseBool(v)
	if err != nil {
		return fallback
	}
	return b
}
