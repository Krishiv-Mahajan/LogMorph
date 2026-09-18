package quarantine

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/Krishiv-Mahajan/LogMorph/internal/models"
	"github.com/Krishiv-Mahajan/LogMorph/internal/storage/postgres"
)

func sampleEntry(eventID string) Entry {
	return Entry{
		EventID:      eventID,
		Stage:        "parsing",
		Type:         "parse_failed",
		Class:        "permanent",
		Message:      "parse_failed: parsing failed for format json: unexpected end of JSON input",
		Attempts:     1,
		RawObjectKey: eventID + ".json",
		RawFormat:    "json",
		RawSource:    "firewall-01",
		StreamID:     "1750000000000-0",
		ConsumerName: "worker-1",
		ReceivedAt:   time.Date(2026, 8, 28, 18, 30, 13, 0, time.UTC),
		RawPayload: &models.RawEvent{
			EventID:    eventID,
			ReceivedAt: "2026-08-28T18:30:13Z",
			Format:     "json",
			Source:     "firewall-01",
			Payload:    `{"broken": `,
		},
	}
}

// ── In-memory store ──────────────────────────────────────────────────────────

func TestMemoryStoreAddAndGet(t *testing.T) {
	ctx := context.Background()
	store := NewMemoryStore()

	if err := store.Add(ctx, sampleEntry("evt_q1")); err != nil {
		t.Fatalf("add failed: %v", err)
	}

	entry, err := store.Get(ctx, "evt_q1")
	if err != nil {
		t.Fatalf("get failed: %v", err)
	}
	if entry.Stage != "parsing" || entry.Type != "parse_failed" {
		t.Errorf("unexpected classification: %+v", entry)
	}
	if entry.RawPayload == nil || entry.RawPayload.Payload != `{"broken": ` {
		t.Error("expected the raw payload to be preserved for investigation")
	}
	if entry.QuarantinedAt.IsZero() {
		t.Error("expected a quarantine timestamp to be set")
	}
}

func TestMemoryStoreAddIsIdempotent(t *testing.T) {
	ctx := context.Background()
	store := NewMemoryStore()

	if err := store.Add(ctx, sampleEntry("evt_q2")); err != nil {
		t.Fatalf("first add failed: %v", err)
	}

	first, err := store.Get(ctx, "evt_q2")
	if err != nil {
		t.Fatalf("get failed: %v", err)
	}

	// Re-quarantining with a higher attempt count must not create a second row.
	second := sampleEntry("evt_q2")
	second.Attempts = 5
	second.Message = "max_attempts_exceeded"
	if err := store.Add(ctx, second); err != nil {
		t.Fatalf("second add failed: %v", err)
	}

	count, err := store.Count(ctx)
	if err != nil {
		t.Fatalf("count failed: %v", err)
	}
	if count != 1 {
		t.Errorf("expected exactly 1 entry, got %d", count)
	}

	updated, err := store.Get(ctx, "evt_q2")
	if err != nil {
		t.Fatalf("get failed: %v", err)
	}
	if updated.Attempts != 5 {
		t.Errorf("expected the attempt count to be updated to 5, got %d", updated.Attempts)
	}
	if !updated.QuarantinedAt.Equal(first.QuarantinedAt) {
		t.Error("expected the original quarantine timestamp to be preserved")
	}
}

func TestMemoryStoreRejectsEmptyEventID(t *testing.T) {
	if err := NewMemoryStore().Add(context.Background(), Entry{}); err == nil {
		t.Error("expected an error for an empty event_id")
	}
}

// ── PostgreSQL store (integration) ───────────────────────────────────────────

func newIntegrationStore(t *testing.T) *PostgresStore {
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

	if err := postgres.Migrate(ctx, db); err != nil {
		t.Fatalf("failed to migrate: %v", err)
	}

	if _, err := db.ExecContext(ctx, `TRUNCATE quarantined_events`); err != nil {
		t.Fatalf("failed to truncate quarantined_events: %v", err)
	}

	return NewPostgresStore(db)
}

func TestPostgresStoreAddAndGet(t *testing.T) {
	store := newIntegrationStore(t)
	ctx := context.Background()

	if err := store.Add(ctx, sampleEntry("evt_pg_q1")); err != nil {
		t.Fatalf("add failed: %v", err)
	}

	entry, err := store.Get(ctx, "evt_pg_q1")
	if err != nil {
		t.Fatalf("get failed: %v", err)
	}
	if entry.Stage != "parsing" {
		t.Errorf("expected stage parsing, got %q", entry.Stage)
	}
	if entry.Type != "parse_failed" {
		t.Errorf("expected type parse_failed, got %q", entry.Type)
	}
	if entry.RawObjectKey != "evt_pg_q1.json" {
		t.Errorf("expected the raw object reference, got %q", entry.RawObjectKey)
	}
	if entry.StreamID != "1750000000000-0" {
		t.Errorf("expected the stream id, got %q", entry.StreamID)
	}
	if entry.ConsumerName != "worker-1" {
		t.Errorf("expected the consumer name, got %q", entry.ConsumerName)
	}
	if entry.Attempts != 1 {
		t.Errorf("expected 1 attempt, got %d", entry.Attempts)
	}
	if entry.QuarantinedAt.IsZero() {
		t.Error("expected a quarantine timestamp")
	}
	if entry.RawPayload == nil || entry.RawPayload.Payload != `{"broken": ` {
		t.Error("expected the raw payload to round-trip through JSONB")
	}
}

// TestPostgresStoreAddIsIdempotent — the primary key on event_id plus ON
// CONFLICT keeps a re-quarantine from creating a second row, and the attempt
// count only moves forward.
func TestPostgresStoreAddIsIdempotent(t *testing.T) {
	store := newIntegrationStore(t)
	ctx := context.Background()

	if err := store.Add(ctx, sampleEntry("evt_pg_q2")); err != nil {
		t.Fatalf("first add failed: %v", err)
	}
	first, err := store.Get(ctx, "evt_pg_q2")
	if err != nil {
		t.Fatalf("get failed: %v", err)
	}

	second := sampleEntry("evt_pg_q2")
	second.Attempts = 7
	second.Stage = "persistence"
	second.Type = "max_attempts_exceeded"
	if err := store.Add(ctx, second); err != nil {
		t.Fatalf("second add failed: %v", err)
	}

	count, err := store.Count(ctx)
	if err != nil {
		t.Fatalf("count failed: %v", err)
	}
	if count != 1 {
		t.Errorf("expected exactly 1 row, got %d", count)
	}

	updated, err := store.Get(ctx, "evt_pg_q2")
	if err != nil {
		t.Fatalf("get failed: %v", err)
	}
	if updated.Attempts != 7 {
		t.Errorf("expected attempts 7, got %d", updated.Attempts)
	}
	if updated.Type != "max_attempts_exceeded" || updated.Stage != "persistence" {
		t.Errorf("expected the newer classification to win, got stage=%q type=%q", updated.Stage, updated.Type)
	}
	if !updated.QuarantinedAt.Equal(first.QuarantinedAt) {
		t.Error("expected the first quarantine timestamp to be preserved")
	}
}

// TestPostgresStoreAcceptsEntryWithoutRawPayload — an event quarantined before
// its raw payload could be marshalled must still be recorded.
func TestPostgresStoreAcceptsEntryWithoutRawPayload(t *testing.T) {
	store := newIntegrationStore(t)
	ctx := context.Background()

	entry := sampleEntry("evt_pg_q3")
	entry.RawPayload = nil
	if err := store.Add(ctx, entry); err != nil {
		t.Fatalf("add failed: %v", err)
	}

	got, err := store.Get(ctx, "evt_pg_q3")
	if err != nil {
		t.Fatalf("get failed: %v", err)
	}
	if got.RawPayload != nil {
		t.Error("expected a nil raw payload to round-trip as nil")
	}
}
