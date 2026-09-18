// Package postgres owns the PostgreSQL connection pool and the reproducible
// schema-initialisation mechanism shared by the normalized and quarantine
// stores.
package postgres

import (
	"context"
	"database/sql"
	"fmt"
	"net/url"
	"os"
	"strconv"
	"time"

	// pgx registers the "pgx" database/sql driver used by this package.
	_ "github.com/jackc/pgx/v5/stdlib"
)

// Config holds PostgreSQL connection settings.
type Config struct {
	// DSN, when set, is used verbatim and takes precedence over the discrete
	// fields below.
	DSN string

	Host     string
	Port     string
	User     string
	Password string
	Database string
	SSLMode  string

	// MaxOpenConns / MaxIdleConns bound the pool. Defaults: 10 / 5.
	MaxOpenConns int
	MaxIdleConns int
}

// ConfigFromEnv builds a Config from environment variables.
//
// POSTGRES_DSN wins when present; otherwise the connection string is assembled
// from POSTGRES_HOST / POSTGRES_PORT / POSTGRES_USER / POSTGRES_PASSWORD /
// POSTGRES_DB / POSTGRES_SSLMODE. No credential is ever hardcoded here.
func ConfigFromEnv() Config {
	cfg := Config{
		DSN:      os.Getenv("POSTGRES_DSN"),
		Host:     os.Getenv("POSTGRES_HOST"),
		Port:     os.Getenv("POSTGRES_PORT"),
		User:     os.Getenv("POSTGRES_USER"),
		Password: os.Getenv("POSTGRES_PASSWORD"),
		Database: os.Getenv("POSTGRES_DB"),
		SSLMode:  os.Getenv("POSTGRES_SSLMODE"),
	}
	if n, err := strconv.Atoi(os.Getenv("POSTGRES_MAX_OPEN_CONNS")); err == nil && n > 0 {
		cfg.MaxOpenConns = n
	}
	if n, err := strconv.Atoi(os.Getenv("POSTGRES_MAX_IDLE_CONNS")); err == nil && n > 0 {
		cfg.MaxIdleConns = n
	}
	return cfg
}

// DSNString resolves the final connection string.
func (c Config) DSNString() string {
	if c.DSN != "" {
		return c.DSN
	}

	host := orDefault(c.Host, "localhost")
	port := orDefault(c.Port, "5432")
	user := orDefault(c.User, "logmorph")
	db := orDefault(c.Database, "logmorph")
	sslMode := orDefault(c.SSLMode, "disable")

	u := &url.URL{
		Scheme: "postgres",
		User:   url.UserPassword(user, c.Password),
		Host:   host + ":" + port,
		Path:   "/" + db,
	}
	q := url.Values{}
	q.Set("sslmode", sslMode)
	u.RawQuery = q.Encode()

	return u.String()
}

// Redacted returns the DSN with the password removed, safe for logs.
func (c Config) Redacted() string {
	raw := c.DSNString()
	u, err := url.Parse(raw)
	if err != nil || u.User == nil {
		return raw
	}

	// Drop the password rather than masking it: a placeholder would still have
	// to be URL-escaped into something unreadable.
	u.User = url.User(u.User.Username())

	return u.String()
}

// Open creates the connection pool and verifies connectivity with a ping.
func Open(ctx context.Context, cfg Config) (*sql.DB, error) {
	db, err := sql.Open("pgx", cfg.DSNString())
	if err != nil {
		return nil, fmt.Errorf("failed to open postgres connection: %w", err)
	}

	maxOpen := cfg.MaxOpenConns
	if maxOpen <= 0 {
		maxOpen = 10
	}
	maxIdle := cfg.MaxIdleConns
	if maxIdle <= 0 {
		maxIdle = 5
	}
	db.SetMaxOpenConns(maxOpen)
	db.SetMaxIdleConns(maxIdle)
	db.SetConnMaxLifetime(30 * time.Minute)

	pingCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	if err := db.PingContext(pingCtx); err != nil {
		db.Close()
		return nil, fmt.Errorf("failed to ping postgres: %w", err)
	}

	return db, nil
}

// OpenWithRetry repeatedly attempts Open until it succeeds or attempts are
// exhausted. It makes container startup resilient to Postgres still booting.
func OpenWithRetry(ctx context.Context, cfg Config, attempts int, delay time.Duration) (*sql.DB, error) {
	if attempts < 1 {
		attempts = 1
	}

	var lastErr error
	for i := 0; i < attempts; i++ {
		db, err := Open(ctx, cfg)
		if err == nil {
			return db, nil
		}
		lastErr = err

		select {
		case <-ctx.Done():
			return nil, fmt.Errorf("postgres connection cancelled: %w", ctx.Err())
		case <-time.After(delay):
		}
	}

	return nil, fmt.Errorf("postgres unavailable after %d attempt(s): %w", attempts, lastErr)
}

func orDefault(val, fallback string) string {
	if val == "" {
		return fallback
	}
	return val
}
