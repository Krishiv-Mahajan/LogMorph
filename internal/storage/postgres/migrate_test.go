package postgres

import (
	"strings"
	"testing"
)

func TestSplitStatements(t *testing.T) {
	tests := []struct {
		name     string
		script   string
		expected int
	}{
		{
			name:     "empty script",
			script:   "   \n\t ",
			expected: 0,
		},
		{
			name:     "two statements",
			script:   "CREATE TABLE a (id int);\nCREATE TABLE b (id int);",
			expected: 2,
		},
		{
			name:     "trailing semicolon produces no empty statement",
			script:   "CREATE TABLE a (id int);",
			expected: 1,
		},
		{
			name:     "statement without trailing semicolon",
			script:   "SELECT 1",
			expected: 1,
		},
		{
			name:     "semicolon inside a string literal",
			script:   "INSERT INTO a VALUES ('x;y'); SELECT 1;",
			expected: 2,
		},
		{
			name:     "escaped quote inside a literal",
			script:   "INSERT INTO a VALUES ('it''s; fine'); SELECT 1;",
			expected: 2,
		},
		{
			name:     "line comment containing a semicolon",
			script:   "-- create a; then b\nCREATE TABLE a (id int);",
			expected: 1,
		},
		{
			name:     "comment markers inside a literal are not comments",
			script:   "INSERT INTO a VALUES ('-- not a comment; really');",
			expected: 1,
		},
		{
			name:     "dollar-quoted body containing semicolons",
			script:   "CREATE FUNCTION f() RETURNS int AS $$ BEGIN; RETURN 1; END; $$ LANGUAGE plpgsql;",
			expected: 1,
		},
		{
			name:     "tagged dollar-quoted body",
			script:   "CREATE FUNCTION f() RETURNS int AS $body$ SELECT 1; $body$ LANGUAGE sql; SELECT 2;",
			expected: 2,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := splitStatements(tt.script)
			if len(got) != tt.expected {
				t.Fatalf("expected %d statement(s), got %d: %#v", tt.expected, len(got), got)
			}
			for _, stmt := range got {
				if strings.TrimSpace(stmt) == "" {
					t.Errorf("splitStatements produced an empty statement: %#v", got)
				}
			}
		})
	}
}

// TestEmbeddedMigrationsParse verifies the shipped migration file is readable
// and splits into the expected statements. It does not need a database.
func TestEmbeddedMigrationsParse(t *testing.T) {
	versions, err := migrationVersions()
	if err != nil {
		t.Fatalf("failed to list migrations: %v", err)
	}
	if len(versions) == 0 {
		t.Fatal("expected at least one embedded migration")
	}
	if versions[0] != "0001_init.sql" {
		t.Errorf("expected 0001_init.sql first, got %q", versions[0])
	}

	content, err := migrationFS.ReadFile("migrations/0001_init.sql")
	if err != nil {
		t.Fatalf("failed to read migration: %v", err)
	}

	statements := splitStatements(string(content))
	if len(statements) < 5 {
		t.Fatalf("expected the init migration to contain several statements, got %d", len(statements))
	}

	joined := strings.Join(statements, "\n")
	for _, expected := range []string{
		"CREATE TABLE IF NOT EXISTS normalized_events",
		"CREATE TABLE IF NOT EXISTS quarantined_events",
		"PRIMARY KEY",
	} {
		if !strings.Contains(joined, expected) {
			t.Errorf("expected the migration to contain %q", expected)
		}
	}

	for _, stmt := range statements {
		if strings.Contains(strings.ToUpper(stmt), "DROP TABLE") {
			t.Errorf("migrations must not drop tables: %q", stmt)
		}
	}
}

func TestConfigDSNString(t *testing.T) {
	cfg := Config{
		Host:     "db.internal",
		Port:     "5433",
		User:     "logmorph",
		Password: "s3cret",
		Database: "logmorph",
		SSLMode:  "require",
	}

	dsn := cfg.DSNString()
	for _, want := range []string{"postgres://", "logmorph:s3cret@db.internal:5433", "/logmorph", "sslmode=require"} {
		if !strings.Contains(dsn, want) {
			t.Errorf("expected DSN to contain %q, got %q", want, dsn)
		}
	}

	// The password must never appear in log output.
	redacted := cfg.Redacted()
	if strings.Contains(redacted, "s3cret") {
		t.Errorf("expected the password to be redacted, got %q", redacted)
	}
	if !strings.Contains(redacted, "logmorph") {
		t.Errorf("expected the username to survive redaction, got %q", redacted)
	}

	// An explicit DSN takes precedence over the discrete fields.
	explicit := Config{DSN: "postgres://u:p@h:1/db", Host: "ignored"}
	if explicit.DSNString() != "postgres://u:p@h:1/db" {
		t.Errorf("expected the explicit DSN to win, got %q", explicit.DSNString())
	}
}

func TestTimestampOrNil(t *testing.T) {
	if got := TimestampOrNil(""); got != nil {
		t.Errorf("expected nil for an empty timestamp, got %v", got)
	}
	if got := TimestampOrNil("not a timestamp"); got != nil {
		t.Errorf("expected nil for an unparseable timestamp, got %v", got)
	}
	if got := TimestampOrNil("2026-08-28T18:30:12Z"); got == nil {
		t.Error("expected RFC3339 to parse")
	}
	if got := TimestampOrNil("Aug 28 18:30:12"); got == nil {
		t.Error("expected a BSD syslog timestamp to parse")
	}
}
