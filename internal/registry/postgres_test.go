package registry

import (
	"context"
	"database/sql"
	"errors"
	"os"
	"sync"
	"testing"

	"github.com/Krishiv-Mahajan/LogMorph/internal/contract"
	"github.com/Krishiv-Mahajan/LogMorph/internal/storage/postgres"
)

// newIntegrationStore skips unless TEST_POSTGRES_DSN points at a reachable
// database, so the default `go test ./...` run needs no services.
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
	lockIntegrationDB(t, db)

	if err := postgres.Migrate(ctx, db); err != nil {
		t.Fatalf("failed to migrate: %v", err)
	}
	if _, err := db.ExecContext(ctx, `TRUNCATE source_registry`); err != nil {
		t.Fatalf("failed to truncate source_registry: %v", err)
	}

	return NewPostgresStore(db), db
}

// integrationLockKey serialises the PostgreSQL integration tests across
// packages. `go test ./...` runs packages in parallel, and these tests truncate
// tables that other packages' tests also use, so the shared database has to be
// held by one package at a time.
const integrationLockKey = 8274615202912

// lockIntegrationDB takes a session-level advisory lock for the duration of the
// test. The connection is held open deliberately: the lock lives on the session,
// so a pooled connection must not be returned while it is held.
func lockIntegrationDB(t *testing.T, db *sql.DB) {
	t.Helper()

	conn, err := db.Conn(context.Background())
	if err != nil {
		t.Fatalf("failed to acquire a connection for the integration lock: %v", err)
	}
	if _, err := conn.ExecContext(context.Background(), `SELECT pg_advisory_lock($1)`, integrationLockKey); err != nil {
		conn.Close()
		t.Fatalf("failed to take the integration lock: %v", err)
	}

	t.Cleanup(func() {
		if _, err := conn.ExecContext(context.Background(), `SELECT pg_advisory_unlock($1)`, integrationLockKey); err != nil {
			t.Logf("failed to release the integration lock: %v", err)
		}
		conn.Close()
	})
}

func TestPostgresStoreVersionChain(t *testing.T) {
	store, _ := newIntegrationStore(t)
	ctx := context.Background()
	fingerprint := "fp_pg_chain"

	if _, err := store.ActiveFor(ctx, fingerprint); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected ErrNotFound for an unknown source, got %v", err)
	}

	v1, err := store.SaveVersion(ctx, sampleEntry(fingerprint, "mapping"))
	if err != nil {
		t.Fatalf("failed to save v1: %v", err)
	}
	if v1.MappingVersion != 1 {
		t.Fatalf("expected version 1, got %d", v1.MappingVersion)
	}

	adapted := sampleEntry(fingerprint, "mapping")
	adapted.Contract = adapted.Contract.WithField(
		contract.Field{Name: "device_uuid", Type: contract.TypeString, Optional: true})
	adapted.ParentVersion = 1
	adapted.DriftStatus = "minor_drift"
	adapted.Rationale = "auto-adapted additive field(s): device_uuid"

	v2, err := store.SaveVersion(ctx, adapted)
	if err != nil {
		t.Fatalf("failed to save v2: %v", err)
	}
	if v2.MappingVersion != 2 {
		t.Fatalf("expected version 2, got %d", v2.MappingVersion)
	}

	// The previous version is superseded, not edited or deleted.
	reloadedV1, err := store.GetVersion(ctx, VersionRef{Fingerprint: fingerprint, MappingID: "mapping", MappingVersion: 1})
	if err != nil {
		t.Fatalf("expected v1 to remain available: %v", err)
	}
	if reloadedV1.Status != StatusSuperseded {
		t.Errorf("expected v1 superseded, got %q", reloadedV1.Status)
	}
	if _, ok := reloadedV1.Contract.Lookup("device_uuid"); ok {
		t.Error("expected v1's contract to be unchanged")
	}

	// The adaptation's lineage survives the round trip.
	if v2.ParentVersion != 1 || v2.DriftStatus != "minor_drift" || v2.Rationale == "" {
		t.Errorf("expected the version lineage to round-trip, got parent=%d drift=%q rationale=%q",
			v2.ParentVersion, v2.DriftStatus, v2.Rationale)
	}

	// Only the newest version is active.
	active, err := store.ActiveFor(ctx, fingerprint)
	if err != nil {
		t.Fatalf("failed to read the active version: %v", err)
	}
	if active.MappingVersion != 2 {
		t.Errorf("expected v2 active, got v%d", active.MappingVersion)
	}

	// The contract survives JSONB storage intact.
	field, ok := active.Contract.Lookup("device_uuid")
	if !ok || !field.Optional || field.Target != "" {
		t.Errorf("expected the adapted field to round-trip as optional and unbound, got %+v", field)
	}
}

// TestPostgresStoreRejectsDuplicateContract — re-observing a change that is
// already recorded must not pile up versions.
func TestPostgresStoreRejectsDuplicateContract(t *testing.T) {
	store, _ := newIntegrationStore(t)
	ctx := context.Background()
	fingerprint := "fp_pg_dedupe"

	if _, err := store.SaveVersion(ctx, sampleEntry(fingerprint, "mapping")); err != nil {
		t.Fatalf("save v1: %v", err)
	}

	adapted := sampleEntry(fingerprint, "mapping")
	adapted.Contract = adapted.Contract.WithField(
		contract.Field{Name: "device_uuid", Type: contract.TypeString, Optional: true})

	first, err := store.SaveVersion(ctx, adapted)
	if err != nil {
		t.Fatalf("save v2: %v", err)
	}
	second, err := store.SaveVersion(ctx, adapted)
	if err != nil {
		t.Fatalf("re-save v2: %v", err)
	}

	if first.MappingVersion != second.MappingVersion {
		t.Errorf("expected the identical contract to reuse v%d, got v%d",
			first.MappingVersion, second.MappingVersion)
	}

	versions, err := store.VersionsFor(ctx, fingerprint)
	if err != nil {
		t.Fatalf("failed to list versions: %v", err)
	}
	if len(versions) != 2 {
		t.Errorf("expected exactly 2 versions, got %d", len(versions))
	}
}

// TestPostgresStoreConcurrentAdaptationAllocatesOneVersion — two workers
// observing the same drift must not create conflicting versions.
func TestPostgresStoreConcurrentAdaptationAllocatesOneVersion(t *testing.T) {
	store, _ := newIntegrationStore(t)
	ctx := context.Background()
	fingerprint := "fp_pg_race"

	if _, err := store.SaveVersion(ctx, sampleEntry(fingerprint, "mapping")); err != nil {
		t.Fatalf("save v1: %v", err)
	}

	adapted := sampleEntry(fingerprint, "mapping")
	adapted.Contract = adapted.Contract.WithField(
		contract.Field{Name: "device_uuid", Type: contract.TypeString, Optional: true})

	const workers = 4
	results := make([]int, workers)
	errs := make([]error, workers)

	var wg sync.WaitGroup
	start := make(chan struct{})
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func(index int) {
			defer wg.Done()
			<-start
			entry, err := store.SaveVersion(ctx, adapted)
			if err != nil {
				errs[index] = err
				return
			}
			results[index] = entry.MappingVersion
		}(i)
	}
	close(start)
	wg.Wait()

	for i, err := range errs {
		if err != nil {
			t.Fatalf("worker %d failed: %v", i, err)
		}
	}
	for i, version := range results {
		if version != 2 {
			t.Errorf("worker %d allocated version %d; expected all workers to agree on v2", i, version)
		}
	}

	versions, err := store.VersionsFor(ctx, fingerprint)
	if err != nil {
		t.Fatalf("failed to list versions: %v", err)
	}
	if len(versions) != 2 {
		t.Errorf("expected exactly 2 versions after a concurrent adaptation, got %d", len(versions))
	}
}

// TestPostgresStoreSurvivesRestart — registry state is durable, so a new
// process reading the same database sees the whole version chain.
func TestPostgresStoreSurvivesRestart(t *testing.T) {
	store, db := newIntegrationStore(t)
	ctx := context.Background()
	fingerprint := "fp_pg_restart"

	if _, err := store.SaveVersion(ctx, sampleEntry(fingerprint, "mapping")); err != nil {
		t.Fatalf("save v1: %v", err)
	}
	adapted := sampleEntry(fingerprint, "mapping")
	adapted.Contract = adapted.Contract.WithField(
		contract.Field{Name: "device_uuid", Type: contract.TypeString, Optional: true})
	if _, err := store.SaveVersion(ctx, adapted); err != nil {
		t.Fatalf("save v2: %v", err)
	}

	// A brand-new pool and store, as a restarted process would build.
	fresh, err := postgres.Open(ctx, postgres.Config{DSN: os.Getenv("TEST_POSTGRES_DSN")})
	if err != nil {
		t.Fatalf("failed to open a second pool: %v", err)
	}
	defer fresh.Close()

	restarted := NewPostgresStore(fresh)

	active, err := restarted.ActiveFor(ctx, fingerprint)
	if err != nil {
		t.Fatalf("a restarted store must see the active mapping: %v", err)
	}
	if active.MappingVersion != 2 {
		t.Errorf("expected v2 active after restart, got v%d", active.MappingVersion)
	}

	versions, err := restarted.VersionsFor(ctx, fingerprint)
	if err != nil {
		t.Fatalf("a restarted store must see the version chain: %v", err)
	}
	if len(versions) != 2 {
		t.Errorf("expected 2 versions after restart, got %d", len(versions))
	}

	// The database rows are the source of truth, independent of the store.
	var count int
	if err := db.QueryRowContext(ctx,
		`SELECT count(*) FROM source_registry WHERE fingerprint = $1`, fingerprint).Scan(&count); err != nil {
		t.Fatalf("failed to count rows: %v", err)
	}
	if count != 2 {
		t.Errorf("expected 2 persisted rows, got %d", count)
	}
}
