package config

import (
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"testing"
)

// setRequiredEnvExceptDatabaseURL sets every other required variable so a
// test can isolate DATABASE_URL / database-name behavior.
func setRequiredEnvExceptDatabaseURL(t *testing.T) {
	t.Helper()
	t.Setenv("REDIS_ADDR", "localhost:6379")
	t.Setenv("JWT_PRIVATE_KEY", "test-key")
	t.Setenv("MEDIA_SERVICE_URL", "http://localhost:8085")
	t.Setenv("APIARY_SERVICE_URL", "http://localhost:8082")
	t.Setenv("HIVE_SERVICE_URL", "http://localhost:8083")
	t.Setenv("INSPECTION_SERVICE_URL", "http://localhost:8084")
	t.Setenv("HARVEST_SERVICE_URL", "http://localhost:8087")
	t.Setenv("NOTIFICATION_SERVICE_URL", "http://localhost:8088")
	t.Setenv("SUBSCRIPTION_SERVICE_URL", "http://localhost:8089")
	t.Setenv("INTERNAL_SERVICE_TOKEN", "test-token")
	t.Setenv("TOTP_ENCRYPTION_KEY", "test-key")
}

// The database name must always come from the environment: there is no
// getEnv("DATABASE_URL", "...some default...") anywhere, so an operator
// who forgets to set it gets a startup error instead of the app silently
// connecting to whatever database happens to be named "beebase".
func TestLoad_RequiresDatabaseURL(t *testing.T) {
	setRequiredEnvExceptDatabaseURL(t)
	t.Setenv("DATABASE_URL", "")

	if _, err := Load(); err == nil {
		t.Fatal("Load() succeeded without DATABASE_URL; the database must never have an implicit default")
	}
}

// Whatever DATABASE_URL the environment provides is used exactly as given
// -- Load must not parse it, rewrite the database name, or otherwise
// second-guess the configured value.
func TestLoad_DatabaseURLComesVerbatimFromEnvironment(t *testing.T) {
	setRequiredEnvExceptDatabaseURL(t)
	const dsn = "postgres://beebase:secret@postgres-auth:5432/beebase_auth?sslmode=disable"
	t.Setenv("DATABASE_URL", dsn)

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() returned error: %v", err)
	}
	if cfg.DatabaseURL != dsn {
		t.Fatalf("DatabaseURL = %q, want exactly %q", cfg.DatabaseURL, dsn)
	}
}

// Regression guard for the beebase -> beebase_auth rename: Load has no
// special-cased logic that would reject, mangle, or fall back away from
// the current production database name.
func TestLoad_AcceptsBeebaseAuthDatabaseName(t *testing.T) {
	setRequiredEnvExceptDatabaseURL(t)
	const dsn = "postgres://beebase:secret@postgres-auth:5432/beebase_auth?sslmode=disable"
	t.Setenv("DATABASE_URL", dsn)

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() returned error: %v", err)
	}
	if !strings.Contains(cfg.DatabaseURL, "/beebase_auth?") {
		t.Fatalf("DatabaseURL %q does not target beebase_auth", cfg.DatabaseURL)
	}
}

// Regression guard for local dev tooling: docker-compose.yml's POSTGRES_DB
// default (and the DSNs built from it) must resolve to beebase_auth, not
// the legacy bare "beebase" this service used before the rename. Scoped
// to the POSTGRES_DB default specifically -- not every occurrence of the
// word "beebase", which legitimately appears elsewhere (POSTGRES_USER,
// image/user names, the project name).
func TestLocalDevComposeDefaultsToBeebaseAuthDatabase(t *testing.T) {
	path := repoFile(t, "docker-compose.yml")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	content := string(data)

	dbDefault := regexp.MustCompile(`POSTGRES_DB:-([a-zA-Z0-9_]+)`)
	matches := dbDefault.FindAllStringSubmatch(content, -1)
	if len(matches) == 0 {
		t.Fatalf("no POSTGRES_DB default found in %s", path)
	}
	for _, m := range matches {
		if m[1] != "beebase_auth" {
			t.Errorf("docker-compose.yml POSTGRES_DB default is %q, want %q", m[1], "beebase_auth")
		}
	}

	dsnDB := regexp.MustCompile(`postgres://[^\s]+@[^/\s]+/\$\{POSTGRES_DB:-([a-zA-Z0-9_]+)\}`)
	dsnMatches := dsnDB.FindAllStringSubmatch(content, -1)
	if len(dsnMatches) == 0 {
		t.Fatalf("no DSN built from POSTGRES_DB found in %s", path)
	}
	for _, m := range dsnMatches {
		if m[1] != "beebase_auth" {
			t.Errorf("docker-compose.yml DSN falls back to database %q, want %q", m[1], "beebase_auth")
		}
	}
}

// No file in the service should contain a CREATE/ALTER/DROP DATABASE
// statement: the application must never create, rename, or drop its own
// database automatically. Scoped to that specific, dangerous SQL pattern
// -- not a generic text search -- so it won't flag unrelated legitimate
// uses of "beebase" or "database" as a plain word.
func TestNoAutomaticDatabaseCreateAlterOrRename(t *testing.T) {
	root := repoFile(t, ".")
	forbidden := regexp.MustCompile(`(?i)\b(create|alter|drop)\s+database\b`)

	var offenders []string
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			switch d.Name() {
			case ".git", "bin", "vendor":
				return filepath.SkipDir
			}
			return nil
		}
		if strings.HasSuffix(path, "_test.go") {
			return nil
		}
		switch filepath.Ext(path) {
		case ".go", ".sql", ".sh":
		default:
			return nil
		}
		data, rerr := os.ReadFile(path)
		if rerr != nil {
			return rerr
		}
		if forbidden.Match(data) {
			rel, _ := filepath.Rel(root, path)
			offenders = append(offenders, rel)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk repo: %v", err)
	}
	if len(offenders) > 0 {
		t.Fatalf("found automatic database CREATE/ALTER/DROP statements (forbidden) in: %v", offenders)
	}
}

// repoFile resolves a path relative to the module root, independent of the
// working directory `go test` happens to be invoked from.
func repoFile(t *testing.T, rel string) string {
	t.Helper()
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	root := filepath.Join(filepath.Dir(thisFile), "..", "..") // internal/config -> repo root
	return filepath.Join(root, rel)
}
