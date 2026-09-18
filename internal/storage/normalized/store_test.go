package normalized

import (
	"context"
	"database/sql"
	"os"
	"testing"
	"time"

	"github.com/Krishiv-Mahajan/LogMorph/internal/models"
	"github.com/Krishiv-Mahajan/LogMorph/internal/storage/postgres"
)

func sampleEvent(eventID string) *models.UniversalEvent {
	srcPort := 54321
	dstPort := 443
	username := "alice"

	return &models.UniversalEvent{
		EventID:       eventID,
		SchemaVersion: "1.0",
		Timestamp:     "2026-08-28T18:30:12Z",
		Source: models.SourceInfo{
			Type:       "firewall",
			Vendor:     "generic",
			Product:    "syslog-firewall",
			Identifier: "firewall-01",
		},
		Event: models.EventInfo{
			Category: "network",
			Action:   "deny",
			Severity: "high",
		},
		Network: &models.NetworkInfo{
			SrcIP:    "192.168.1.20",
			SrcPort:  &srcPort,
			DstIP:    "10.0.0.15",
			DstPort:  &dstPort,
			Protocol: "TCP",
		},
		User: &models.UserInfo{Username: &username},
		Raw: models.RawInfo{
			Format:  "syslog",
			Message: "Aug 28 18:30:12 firewall01 DENY TCP",
		},
		Metadata: models.MetadataInfo{
			ParserVersion: "1.0",
			IngestedAt:    "2026-08-28T18:30:13Z",
		},
	}
}

func sampleRecord(eventID string) Record {
	return Record{
		Event:        sampleEvent(eventID),
		RawObjectKey: eventID + ".json",
		ReceivedAt:   time.Date(2026, 8, 28, 18, 30, 13, 0, time.UTC),
	}
}

// ── In-memory store ──────────────────────────────────────────────────────────

func TestMemoryStoreSaveAndGet(t *testing.T) {
	ctx := context.Background()
	store := NewMemoryStore()

	inserted, err := store.Save(ctx, sampleRecord("evt_1"))
	if err != nil {
		t.Fatalf("save failed: %v", err)
	}
	if !inserted {
		t.Error("expected the first save to insert")
	}

	rec, err := store.Get(ctx, "evt_1")
	if err != nil {
		t.Fatalf("get failed: %v", err)
	}
	if rec.Event.EventID != "evt_1" {
		t.Errorf("expected event id evt_1, got %q", rec.Event.EventID)
	}
	if rec.Event.Network == nil || *rec.Event.Network.SrcPort != 54321 {
		t.Errorf("expected the network fields to round-trip, got %+v", rec.Event.Network)
	}
	if rec.RawObjectKey != "evt_1.json" {
		t.Errorf("expected the raw object key to round-trip, got %q", rec.RawObjectKey)
	}
}

// TestMemoryStoreSaveIsIdempotent — the contract the duplicate-suppression
// logic in PostgreSQL mirrors.
func TestMemoryStoreSaveIsIdempotent(t *testing.T) {
	ctx := context.Background()
	store := NewMemoryStore()

	if _, err := store.Save(ctx, sampleRecord("evt_dup")); err != nil {
		t.Fatalf("first save failed: %v", err)
	}

	inserted, err := store.Save(ctx, sampleRecord("evt_dup"))
	if err != nil {
		t.Fatalf("second save failed: %v", err)
	}
	if inserted {
		t.Error("expected a duplicate event_id to be ignored")
	}

	count, err := store.Count(ctx)
	if err != nil {
		t.Fatalf("count failed: %v", err)
	}
	if count != 1 {
		t.Errorf("expected exactly 1 record, got %d", count)
	}
}

func TestMemoryStoreRejectsInvalidRecords(t *testing.T) {
	ctx := context.Background()
	store := NewMemoryStore()

	if _, err := store.Save(ctx, Record{}); err == nil {
		t.Error("expected an error for a nil event")
	}
	if _, err := store.Save(ctx, Record{Event: &models.UniversalEvent{}}); err == nil {
		t.Error("expected an error for an empty event_id")
	}
}

// ── PostgreSQL store (integration) ───────────────────────────────────────────

// newIntegrationStore skips the test unless TEST_POSTGRES_DSN points at a
// reachable database, so the default `go test ./...` run needs no services.
func newIntegrationStore(t *testing.T) (*PostgresStore, *sql.DB) {
	t.Helper()

	dsn := os.Getenv("TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("TEST_POSTGRES_DSN is not set; skipping PostgreSQL integration test")
	}

	ctx := context.Background()
	db, err := postgres.Open(ctx, postgres.Config{DSN: dsn})
	if err != nil {
		t.Fatalf("failed to connect to PostgreSQL: %v", err)
	}
	t.Cleanup(func() { db.Close() })

	// Safe to run concurrently with the quarantine package: the migrator takes
	// an advisory lock.
	if err := postgres.Migrate(ctx, db); err != nil {
		t.Fatalf("failed to migrate: %v", err)
	}
	if err := postgres.Migrate(ctx, db); err != nil {
		t.Fatalf("re-running migrations must be a no-op: %v", err)
	}

	if _, err := db.ExecContext(ctx, `TRUNCATE normalized_events`); err != nil {
		t.Fatalf("failed to truncate normalized_events: %v", err)
	}

	return NewPostgresStore(db), db
}

func TestPostgresStoreSaveAndGet(t *testing.T) {
	store, db := newIntegrationStore(t)
	ctx := context.Background()

	rec := sampleRecord("evt_pg_1")
	inserted, err := store.Save(ctx, rec)
	if err != nil {
		t.Fatalf("save failed: %v", err)
	}
	if !inserted {
		t.Error("expected the first save to insert")
	}

	got, err := store.Get(ctx, "evt_pg_1")
	if err != nil {
		t.Fatalf("get failed: %v", err)
	}
	if got.Event.EventID != "evt_pg_1" {
		t.Errorf("expected evt_pg_1, got %q", got.Event.EventID)
	}
	if got.Event.Event.Action != "deny" || got.Event.Event.Severity != "high" {
		t.Errorf("expected the event fields to round-trip, got %+v", got.Event.Event)
	}
	if got.Event.Network == nil || got.Event.Network.SrcIP != "192.168.1.20" {
		t.Errorf("expected network fields to round-trip, got %+v", got.Event.Network)
	}
	if got.RawObjectKey != "evt_pg_1.json" {
		t.Errorf("expected the raw object key to round-trip, got %q", got.RawObjectKey)
	}

	// The extracted columns are queryable without unpacking the payload.
	var (
		action string
		srcIP  string
		port   int
	)
	err = db.QueryRowContext(ctx,
		`SELECT event_action, src_ip, src_port FROM normalized_events WHERE event_id = $1`,
		"evt_pg_1").Scan(&action, &srcIP, &port)
	if err != nil {
		t.Fatalf("failed to read extracted columns: %v", err)
	}
	if action != "deny" || srcIP != "192.168.1.20" || port != 54321 {
		t.Errorf("unexpected extracted columns: action=%q src_ip=%q src_port=%d", action, srcIP, port)
	}
}

// TestPostgresStoreDuplicateIsIgnored is the database-level half of the
// duplicate-suppression guarantee: ON CONFLICT (event_id) DO NOTHING.
func TestPostgresStoreDuplicateIsIgnored(t *testing.T) {
	store, _ := newIntegrationStore(t)
	ctx := context.Background()

	if _, err := store.Save(ctx, sampleRecord("evt_pg_dup")); err != nil {
		t.Fatalf("first save failed: %v", err)
	}

	inserted, err := store.Save(ctx, sampleRecord("evt_pg_dup"))
	if err != nil {
		t.Fatalf("second save failed: %v", err)
	}
	if inserted {
		t.Error("expected the duplicate event_id to be ignored")
	}

	count, err := store.Count(ctx)
	if err != nil {
		t.Fatalf("count failed: %v", err)
	}
	if count != 1 {
		t.Errorf("expected exactly 1 row, got %d", count)
	}
}

// TestPostgresStoreToleratesOddTimestamps — an exotic timestamp must not turn
// into a database error, which the worker would retry as if it were an outage.
func TestPostgresStoreToleratesOddTimestamps(t *testing.T) {
	store, _ := newIntegrationStore(t)
	ctx := context.Background()

	rec := sampleRecord("evt_pg_ts")
	rec.Event.Timestamp = "not-a-timestamp"
	rec.Event.Metadata.IngestedAt = ""

	inserted, err := store.Save(ctx, rec)
	if err != nil {
		t.Fatalf("expected an unparseable timestamp to be stored as NULL, got: %v", err)
	}
	if !inserted {
		t.Error("expected the row to be inserted")
	}

	got, err := store.Get(ctx, "evt_pg_ts")
	if err != nil {
		t.Fatalf("get failed: %v", err)
	}
	// The original string is preserved in the payload even though the column is NULL.
	if got.Event.Timestamp != "not-a-timestamp" {
		t.Errorf("expected the original timestamp in the payload, got %q", got.Event.Timestamp)
	}
}
