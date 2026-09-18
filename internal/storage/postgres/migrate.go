package postgres

import (
	"context"
	"database/sql"
	"embed"
	"fmt"
	"io/fs"
	"log"
	"sort"
	"strings"
)

//go:embed migrations/*.sql
var migrationFS embed.FS

// migrationLockKey is an arbitrary application-level advisory lock key. It
// serialises migrations when several workers start at the same time.
const migrationLockKey = 8274615202911

const createMigrationsTable = `
CREATE TABLE IF NOT EXISTS schema_migrations (
    version    TEXT        PRIMARY KEY,
    applied_at TIMESTAMPTZ NOT NULL DEFAULT now()
)`

// Migrate applies every embedded migration that has not been applied yet, in
// lexical filename order. Each migration runs inside its own transaction and is
// recorded in schema_migrations, so re-running is a no-op and a failed
// migration is rolled back rather than partially applied.
//
// It is safe to call concurrently from multiple workers: a PostgreSQL advisory
// lock serialises the run.
func Migrate(ctx context.Context, db *sql.DB) error {
	conn, err := db.Conn(ctx)
	if err != nil {
		return fmt.Errorf("failed to acquire connection for migration: %w", err)
	}
	defer conn.Close()

	if _, err := conn.ExecContext(ctx, `SELECT pg_advisory_lock($1)`, migrationLockKey); err != nil {
		return fmt.Errorf("failed to acquire migration advisory lock: %w", err)
	}
	defer func() {
		if _, err := conn.ExecContext(context.WithoutCancel(ctx), `SELECT pg_advisory_unlock($1)`, migrationLockKey); err != nil {
			log.Printf("[Postgres] Warning: failed to release migration advisory lock: %v", err)
		}
	}()

	if _, err := conn.ExecContext(ctx, createMigrationsTable); err != nil {
		return fmt.Errorf("failed to create schema_migrations table: %w", err)
	}

	applied, err := appliedVersions(ctx, conn)
	if err != nil {
		return err
	}

	versions, err := migrationVersions()
	if err != nil {
		return err
	}

	for _, version := range versions {
		if applied[version] {
			continue
		}

		content, err := migrationFS.ReadFile("migrations/" + version)
		if err != nil {
			return fmt.Errorf("failed to read migration %s: %w", version, err)
		}

		if err := applyMigration(ctx, conn, version, string(content)); err != nil {
			return err
		}

		log.Printf("[Postgres] Applied migration %s", version)
	}

	return nil
}

// applyMigration runs one migration file and records it, atomically.
func applyMigration(ctx context.Context, conn *sql.Conn, version, content string) error {
	tx, err := conn.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("failed to begin transaction for migration %s: %w", version, err)
	}
	defer tx.Rollback() //nolint:errcheck // no-op once committed

	// The driver does not accept several statements in one call, so the file is
	// split into individual statements.
	for _, stmt := range splitStatements(content) {
		if _, err := tx.ExecContext(ctx, stmt); err != nil {
			return fmt.Errorf("migration %s failed: %w", version, err)
		}
	}

	if _, err := tx.ExecContext(ctx,
		`INSERT INTO schema_migrations (version) VALUES ($1)`, version); err != nil {
		return fmt.Errorf("failed to record migration %s: %w", version, err)
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit migration %s: %w", version, err)
	}

	return nil
}

func appliedVersions(ctx context.Context, conn *sql.Conn) (map[string]bool, error) {
	rows, err := conn.QueryContext(ctx, `SELECT version FROM schema_migrations`)
	if err != nil {
		return nil, fmt.Errorf("failed to read applied migrations: %w", err)
	}
	defer rows.Close()

	applied := make(map[string]bool)
	for rows.Next() {
		var version string
		if err := rows.Scan(&version); err != nil {
			return nil, fmt.Errorf("failed to scan migration version: %w", err)
		}
		applied[version] = true
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("failed to iterate applied migrations: %w", err)
	}

	return applied, nil
}

// migrationVersions lists embedded migration filenames in application order.
func migrationVersions() ([]string, error) {
	entries, err := fs.ReadDir(migrationFS, "migrations")
	if err != nil {
		return nil, fmt.Errorf("failed to list embedded migrations: %w", err)
	}

	versions := make([]string, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".sql") {
			continue
		}
		versions = append(versions, entry.Name())
	}
	sort.Strings(versions)

	return versions, nil
}

// splitStatements splits a SQL script into executable statements, ignoring
// semicolons inside string literals, dollar-quoted bodies, and comments.
// Empty statements (e.g. a trailing semicolon) are dropped.
func splitStatements(script string) []string {
	var (
		statements []string
		current    strings.Builder
		dollarTag  string
	)

	runes := []rune(script)
	for i := 0; i < len(runes); i++ {
		ch := runes[i]

		switch {
		case dollarTag != "":
			// Inside a $tag$ ... $tag$ body: emit until the closing tag.
			if ch == '$' && hasPrefixAt(runes, i, dollarTag) {
				current.WriteString(dollarTag)
				i += len(dollarTag) - 1
				dollarTag = ""
				continue
			}
			current.WriteRune(ch)

		case ch == '-' && i+1 < len(runes) && runes[i+1] == '-':
			// Line comment: drop it, keep the newline.
			for i < len(runes) && runes[i] != '\n' {
				i++
			}
			current.WriteRune('\n')

		case ch == '\'':
			// Single-quoted literal: consumed atomically so that ';' or '--'
			// inside it are never treated as syntax.
			current.WriteRune(ch)
			i++
			for i < len(runes) {
				current.WriteRune(runes[i])
				if runes[i] == '\'' {
					if i+1 < len(runes) && runes[i+1] == '\'' {
						current.WriteRune(runes[i+1]) // escaped quote
						i += 2
						continue
					}
					break
				}
				i++
			}

		case ch == '$':
			// Dollar-quoted body start, e.g. $$ ... $$ or $body$ ... $body$.
			if tag := readDollarTag(runes, i); tag != "" {
				current.WriteString(tag)
				i += len(tag) - 1
				dollarTag = tag
				continue
			}
			current.WriteRune(ch)

		case ch == ';':
			if stmt := strings.TrimSpace(current.String()); stmt != "" {
				statements = append(statements, stmt)
			}
			current.Reset()

		default:
			current.WriteRune(ch)
		}
	}

	if stmt := strings.TrimSpace(current.String()); stmt != "" {
		statements = append(statements, stmt)
	}

	return statements
}

// readDollarTag returns the dollar-quote tag starting at i (e.g. "$$" or
// "$body$"), or "" when the character is a plain dollar sign.
func readDollarTag(runes []rune, i int) string {
	if runes[i] != '$' {
		return ""
	}
	for j := i + 1; j < len(runes); j++ {
		switch {
		case runes[j] == '$':
			return string(runes[i : j+1])
		case (runes[j] >= 'a' && runes[j] <= 'z') ||
			(runes[j] >= 'A' && runes[j] <= 'Z') ||
			(runes[j] >= '0' && runes[j] <= '9') ||
			runes[j] == '_':
			continue
		default:
			return ""
		}
	}
	return ""
}

func hasPrefixAt(runes []rune, i int, prefix string) bool {
	p := []rune(prefix)
	if i+len(p) > len(runes) {
		return false
	}
	for k, r := range p {
		if runes[i+k] != r {
			return false
		}
	}
	return true
}
