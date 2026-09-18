package tests

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/Krishiv-Mahajan/LogMorph/internal/buffer"
	"github.com/Krishiv-Mahajan/LogMorph/internal/detection"
	"github.com/Krishiv-Mahajan/LogMorph/internal/drift"
	"github.com/Krishiv-Mahajan/LogMorph/internal/ingestion"
	"github.com/Krishiv-Mahajan/LogMorph/internal/models"
	"github.com/Krishiv-Mahajan/LogMorph/internal/normalization"
	"github.com/Krishiv-Mahajan/LogMorph/internal/parsing"
	"github.com/Krishiv-Mahajan/LogMorph/internal/parsing/parsers"
	"github.com/Krishiv-Mahajan/LogMorph/internal/registry"
	"github.com/Krishiv-Mahajan/LogMorph/internal/storage/normalized"
	"github.com/Krishiv-Mahajan/LogMorph/internal/storage/postgres"
	"github.com/Krishiv-Mahajan/LogMorph/internal/storage/quarantine"
	"github.com/Krishiv-Mahajan/LogMorph/internal/storage/raw"
	"github.com/Krishiv-Mahajan/LogMorph/internal/validation"
	"github.com/Krishiv-Mahajan/LogMorph/internal/worker"
)

// driftStack is a fully wired pipeline whose backends can be swapped between
// in-memory and PostgreSQL implementations.
type driftStack struct {
	handler       *ingestion.Handler
	buf           *inMemoryBuffer
	worker        *worker.Worker
	rawStore      raw.RawEventStore
	normalized    normalized.Store
	quarantine    quarantine.Store
	registryStore registry.Store
}

// buildDriftStack wires HTTP -> Redis -> worker -> MinIO -> detection -> drift
// -> parser -> normalization -> validation -> stores.
func buildDriftStack(
	t *testing.T,
	registryStore registry.Store,
	rawStore raw.RawEventStore,
	normalizedStore normalized.Store,
	quarantineStore quarantine.Store,
) *driftStack {
	t.Helper()

	rawBuf := &inMemoryBuffer{}

	parserRegistry := parsing.NewRegistry()
	parserRegistry.Register(parsers.NewSyslogParser())
	parserRegistry.Register(parsers.NewJSONParser())
	parserRegistry.Register(parsers.NewCSVParser())

	validator, err := validation.NewValidator("")
	if err != nil {
		t.Fatalf("failed to create validator: %v", err)
	}

	w := worker.NewWorker(
		rawBuf,
		buffer.NewMemoryIdempotencyStore(),
		rawStore,
		detection.NewDetector(),
		parsing.NewEngine(parserRegistry),
		normalization.NewNormalizer(),
		validator,
		worker.Config{
			StreamName:      "raw_events",
			GroupName:       "test-group",
			ConsumerName:    "test-worker",
			BatchSize:       10,
			Concurrency:     2,
			NormalizedStore: normalizedStore,
			QuarantineStore: quarantineStore,
			DriftAnalyzer:   drift.NewEngine(registryStore, parserRegistry),
		},
	)

	return &driftStack{
		handler:       ingestion.NewHandler(ingestion.NewService(rawBuf, "raw_events")),
		buf:           rawBuf,
		worker:        w,
		rawStore:      rawStore,
		normalized:    normalizedStore,
		quarantine:    quarantineStore,
		registryStore: registryStore,
	}
}

// runWorkerUntil starts the worker and waits for the store to reach a count.
func (s *driftStack) runWorkerUntil(t *testing.T, want int64, what string) {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = s.worker.Start(ctx)
	}()
	defer func() {
		cancel()
		<-done
	}()

	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if count, err := s.normalized.Count(context.Background()); err == nil && count >= want {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}

	count, _ := s.normalized.Count(context.Background())
	t.Fatalf("timed out waiting for %s: normalized count is %d, wanted %d", what, count, want)
}

// TestDriftE2E_AdaptiveMapping walks the phase-6 scenario end to end:
//
//	event 1: known source, stable, mapping v1
//	event 2: same source, new optional field, minor drift, mapping v2
//
// and verifies both events are persisted with the provenance that identifies
// the version that processed each one.
func TestDriftE2E_AdaptiveMapping(t *testing.T) {
	stack := buildDriftStack(t,
		registry.NewMemoryStore(),
		raw.NewMemoryRawStore(),
		normalized.NewMemoryStore(),
		quarantine.NewMemoryStore(),
	)

	const eventOne = `{"timestamp":"2026-08-28T18:30:12Z","firewall":{"action":"deny","protocol":"TCP"},` +
		`"network":{"source":{"ip":"192.168.1.20","port":54321},"destination":{"ip":"10.0.0.15","port":443}}}`

	// A later firmware adds a field. Same source, same format.
	const eventTwo = `{"timestamp":"2026-08-28T18:30:12Z","device_uuid":"fw-9f2c","firewall":{"action":"deny","protocol":"TCP"},` +
		`"network":{"source":{"ip":"192.168.1.20","port":54321},"destination":{"ip":"10.0.0.15","port":443}}}`

	eventIDOne := ingest(t, stack.handler, "json", eventOne)
	stack.runWorkerUntil(t, 1, "the first event to be persisted")

	eventIDTwo := ingest(t, stack.handler, "json", eventTwo)
	stack.runWorkerUntil(t, 2, "the second event to be persisted")

	// ── Both events persisted ────────────────────────────────────────────────
	first, err := stack.normalized.Get(context.Background(), eventIDOne)
	if err != nil {
		t.Fatalf("expected the first event in the normalized store: %v", err)
	}
	second, err := stack.normalized.Get(context.Background(), eventIDTwo)
	if err != nil {
		t.Fatalf("expected the second event in the normalized store: %v", err)
	}

	// ── Raw MinIO references remain correct ──────────────────────────────────
	for eventID, rec := range map[string]*normalized.Record{eventIDOne: first, eventIDTwo: second} {
		if rec.RawObjectKey != raw.ObjectKey(eventID) {
			t.Errorf("expected raw object key %q, got %q", raw.ObjectKey(eventID), rec.RawObjectKey)
		}
		stored, err := stack.rawStore.Get(context.Background(), eventID)
		if err != nil {
			t.Fatalf("expected the immutable raw copy for %s: %v", eventID, err)
		}
		if stored.Payload == "" {
			t.Errorf("expected a raw payload for %s", eventID)
		}
	}

	// ── Provenance identifies the correct parser and mapping version ─────────
	if first.Provenance.MappingVersion != 1 {
		t.Errorf("expected the stable event on mapping v1, got v%d", first.Provenance.MappingVersion)
	}
	if second.Provenance.MappingVersion != 2 {
		t.Errorf("expected the drifted event on mapping v2, got v%d", second.Provenance.MappingVersion)
	}
	if first.Provenance.ParserID != "generic_json" || second.Provenance.ParserID != "generic_json" {
		t.Errorf("expected the json parser on both events, got %q / %q",
			first.Provenance.ParserID, second.Provenance.ParserID)
	}
	if first.Provenance.DriftStatus != string(models.DriftStatusStable) {
		t.Errorf("expected the first event to record stable drift, got %q", first.Provenance.DriftStatus)
	}
	if second.Provenance.DriftStatus != string(models.DriftStatusMinorDrift) {
		t.Errorf("expected the second event to record minor drift, got %q", second.Provenance.DriftStatus)
	}
	if first.Provenance.SourceFingerprint == "" ||
		first.Provenance.SourceFingerprint != second.Provenance.SourceFingerprint {
		t.Error("expected both events to share one source fingerprint")
	}
	if first.Provenance.MappingID != second.Provenance.MappingID {
		t.Error("expected the mapping id to stay stable across versions")
	}

	// The event payload is self-describing, so the row and the JSONB agree.
	if second.Event.Metadata.MappingVersion != 2 || second.Event.Metadata.ParserID != "generic_json" {
		t.Errorf("expected the event metadata to carry provenance, got %+v", second.Event.Metadata)
	}

	// ── The old mapping remains available ────────────────────────────────────
	oldVersion, err := stack.registryStore.GetVersion(context.Background(), registry.VersionRef{
		Fingerprint:    first.Provenance.SourceFingerprint,
		MappingID:      first.Provenance.MappingID,
		MappingVersion: 1,
	})
	if err != nil {
		t.Fatalf("expected mapping v1 to remain available: %v", err)
	}
	if oldVersion.Status != registry.StatusSuperseded {
		t.Errorf("expected v1 to be superseded, got %q", oldVersion.Status)
	}
	if _, ok := oldVersion.Contract.Lookup("device_uuid"); ok {
		t.Error("expected v1 not to contain the later addition")
	}

	newVersion, err := stack.registryStore.GetVersion(context.Background(), registry.VersionRef{
		Fingerprint:    second.Provenance.SourceFingerprint,
		MappingID:      second.Provenance.MappingID,
		MappingVersion: 2,
	})
	if err != nil {
		t.Fatalf("expected mapping v2: %v", err)
	}
	added, ok := newVersion.Contract.Lookup("device_uuid")
	if !ok {
		t.Fatal("expected v2 to declare the adapted field")
	}
	if !added.Optional || added.Target != "" {
		t.Errorf("expected the adapted field to be optional and unbound, got %+v", added)
	}

	// Nothing was quarantined: a safe adaptation is not a failure.
	if count, _ := stack.quarantine.Count(context.Background()); count != 0 {
		t.Errorf("expected no quarantine entries, got %d", count)
	}
}

// TestDriftE2E_UnsafeDriftIsNotAdapted — an unsafe change is escalated and the
// event still ends up somewhere durable rather than disappearing.
func TestDriftE2E_UnsafeDriftIsNotAdapted(t *testing.T) {
	stack := buildDriftStack(t,
		registry.NewMemoryStore(),
		raw.NewMemoryRawStore(),
		normalized.NewMemoryStore(),
		quarantine.NewMemoryStore(),
	)

	const eventOne = `{"timestamp":"2026-08-28T18:30:12Z","firewall":{"action":"deny"}}`
	// The timestamp - a required field - disappears.
	const eventTwo = `{"firewall":{"action":"deny"},"device_uuid":"fw-9f2c"}`

	ingest(t, stack.handler, "json", eventOne)
	stack.runWorkerUntil(t, 1, "the first event to be persisted")

	eventIDTwo := ingest(t, stack.handler, "json", eventTwo)
	stack.runWorkerUntil(t, 2, "the second event to be persisted or quarantined")

	// The event is still processed with the last known-good mapping: it parsed
	// and validated, so it is stored, but its provenance says the source drifted
	// in a way that needs review.
	rec, err := stack.normalized.Get(context.Background(), eventIDTwo)
	if err != nil {
		t.Fatalf("expected the unsafe-drift event to be persisted: %v", err)
	}
	if rec.Provenance.DriftStatus != string(models.DriftStatusMajorDrift) {
		t.Errorf("expected major drift to be recorded, got %q", rec.Provenance.DriftStatus)
	}
	if rec.Provenance.MappingVersion != 1 {
		t.Errorf("expected the active mapping to stay at v1, got v%d", rec.Provenance.MappingVersion)
	}

	versions, err := stack.registryStore.VersionsFor(context.Background(), rec.Provenance.SourceFingerprint)
	if err != nil {
		t.Fatalf("failed to list versions: %v", err)
	}
	if len(versions) != 1 {
		t.Errorf("expected no new mapping version to be created, got %d versions", len(versions))
	}
}

// ── PostgreSQL-backed end-to-end ─────────────────────────────────────────────

func TestDriftE2E_Postgres(t *testing.T) {
	dsn := os.Getenv("TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("TEST_POSTGRES_DSN is not set; skipping PostgreSQL end-to-end test")
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
	for _, table := range []string{"normalized_events", "quarantined_events", "source_registry"} {
		if _, err := db.ExecContext(ctx, "TRUNCATE "+table); err != nil {
			t.Fatalf("failed to truncate %s: %v", table, err)
		}
	}

	stack := buildDriftStack(t,
		registry.NewPostgresStore(db),
		raw.NewMemoryRawStore(), // object storage is out of scope here; MinIO is verified separately
		normalized.NewPostgresStore(db),
		quarantine.NewPostgresStore(db),
	)

	const eventOne = `{"timestamp":"2026-08-28T18:30:12Z","firewall":{"action":"deny","protocol":"TCP"},` +
		`"network":{"source":{"ip":"192.168.1.20","port":54321},"destination":{"ip":"10.0.0.15","port":443}}}`
	const eventTwo = `{"timestamp":"2026-08-28T18:30:12Z","device_uuid":"fw-9f2c","firewall":{"action":"deny","protocol":"TCP"},` +
		`"network":{"source":{"ip":"192.168.1.20","port":54321},"destination":{"ip":"10.0.0.15","port":443}}}`

	eventIDOne := ingest(t, stack.handler, "json", eventOne)
	stack.runWorkerUntil(t, 1, "the first event to reach PostgreSQL")

	eventIDTwo := ingest(t, stack.handler, "json", eventTwo)
	stack.runWorkerUntil(t, 2, "the second event to reach PostgreSQL")

	first, err := stack.normalized.Get(ctx, eventIDOne)
	if err != nil {
		t.Fatalf("expected the first event: %v", err)
	}
	second, err := stack.normalized.Get(ctx, eventIDTwo)
	if err != nil {
		t.Fatalf("expected the second event: %v", err)
	}
	if first.Provenance.MappingVersion != 1 || second.Provenance.MappingVersion != 2 {
		t.Errorf("expected mapping v1 then v2, got v%d then v%d",
			first.Provenance.MappingVersion, second.Provenance.MappingVersion)
	}

	// The registry rows are queryable and joinable with the event rows.
	var (
		version int
		status  string
		parser  string
	)
	if err := db.QueryRowContext(ctx,
		`SELECT mapping_version, status, parser_id FROM source_registry
         WHERE fingerprint = $1 AND mapping_version = 1`,
		first.Provenance.SourceFingerprint).Scan(&version, &status, &parser); err != nil {
		t.Fatalf("failed to read the registry row: %v", err)
	}
	if version != 1 || status != string(registry.StatusSuperseded) || parser != "generic_json" {
		t.Errorf("unexpected registry row: version=%d status=%q parser=%q", version, status, parser)
	}

	// The join that traceability is for: event -> parser/mapping version.
	var joined int
	err = db.QueryRowContext(ctx,
		`SELECT count(*) FROM normalized_events e
         JOIN source_registry r
           ON r.fingerprint = e.source_fingerprint
          AND r.mapping_id = e.mapping_id
          AND r.mapping_version = e.mapping_version`).Scan(&joined)
	if err != nil {
		t.Fatalf("failed to join events to the registry: %v", err)
	}
	if joined != 2 {
		t.Errorf("expected both events to join to their registry version, got %d", joined)
	}

	var nullProvenance int
	if err := db.QueryRowContext(ctx,
		`SELECT count(*) FROM normalized_events
         WHERE source_fingerprint IS NULL OR parser_id IS NULL
            OR mapping_id IS NULL OR mapping_version IS NULL OR drift_status IS NULL`).Scan(&nullProvenance); err != nil {
		t.Fatalf("failed to check provenance completeness: %v", err)
	}
	if nullProvenance != 0 {
		t.Errorf("expected every stored event to carry full provenance, %d without", nullProvenance)
	}
}
