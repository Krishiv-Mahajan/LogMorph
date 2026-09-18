package review

import (
	"context"
	"database/sql"
	"errors"
	"os"
	"sync"
	"testing"

	"github.com/Krishiv-Mahajan/LogMorph/internal/contract"
	"github.com/Krishiv-Mahajan/LogMorph/internal/registry"
	"github.com/Krishiv-Mahajan/LogMorph/internal/storage/postgres"
)

// newIntegrationStores skips unless TEST_POSTGRES_DSN points at a reachable
// database, so the default `go test ./...` run needs no services.
func newIntegrationStores(t *testing.T) (*PostgresStore, *registry.PostgresStore, *sql.DB) {
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
	for _, table := range []string{"source_reviews", "source_registry"} {
		if _, err := db.ExecContext(ctx, "TRUNCATE "+table); err != nil {
			t.Fatalf("failed to truncate %s: %v", table, err)
		}
	}

	return NewPostgresStore(db), registry.NewPostgresStore(db), db
}

// seedMapping registers a base mapping version for a source.
func seedMapping(t *testing.T, mappings *registry.PostgresStore, fingerprint string) *registry.Entry {
	t.Helper()

	entry, err := mappings.SaveVersion(context.Background(), registry.Entry{
		Fingerprint:   fingerprint,
		Vendor:        "generic",
		Product:       "json-firewall",
		SourceType:    "firewall",
		Format:        "json",
		ParserID:      "generic_json",
		ParserVersion: "1.0",
		MappingID:     "generic_json_mapping",
		Status:        registry.StatusActive,
		Contract: contract.Contract{Fields: []contract.Field{
			{Name: "timestamp", Type: contract.TypeString, Target: "timestamp"},
		}},
		DriftStatus: "stable",
		Rationale:   "base mapping",
	})
	if err != nil {
		t.Fatalf("failed to seed mapping: %v", err)
	}

	return entry
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

func TestPostgresStoreUpsertAndGet(t *testing.T) {
	store, _, _ := newIntegrationStores(t)
	ctx := context.Background()

	item := sampleItem()
	item.Changes = append(item.Changes, Change{Kind: "structural_change", Field: "network", Safe: false})

	stored, err := store.Upsert(ctx, item)
	if err != nil {
		t.Fatalf("upsert failed: %v", err)
	}
	if stored.ReviewID == 0 {
		t.Fatal("expected a generated review id")
	}

	reloaded, err := store.Get(ctx, stored.ReviewID)
	if err != nil {
		t.Fatalf("get failed: %v", err)
	}

	if reloaded.Fingerprint != item.Fingerprint || reloaded.Signature != stored.Signature {
		t.Errorf("identity did not round-trip: %+v", reloaded)
	}
	if reloaded.Category != CategoryMappingConflict || reloaded.Status != StatusPending {
		t.Errorf("unexpected category/status: %s / %s", reloaded.Category, reloaded.Status)
	}
	if reloaded.MappingID != item.MappingID || reloaded.MappingVersion != item.MappingVersion {
		t.Errorf("mapping context did not round-trip: %s v%d", reloaded.MappingID, reloaded.MappingVersion)
	}
	if len(reloaded.Changes) != 3 || reloaded.Changes[0].Kind == "" {
		t.Errorf("changes did not round-trip through JSONB: %+v", reloaded.Changes)
	}
	if reloaded.Occurrences != 1 || reloaded.Origin != OriginDriftEngine {
		t.Errorf("unexpected counters: occurrences=%d origin=%q", reloaded.Occurrences, reloaded.Origin)
	}
	if reloaded.FirstSeenAt.IsZero() || reloaded.DecidedAt != nil {
		t.Error("unexpected timestamps on a new item")
	}
}

// TestPostgresStoreDeduplicates is the guarantee that keeps the queue bounded:
// repeated identical drift updates one row.
func TestPostgresStoreDeduplicates(t *testing.T) {
	store, _, _ := newIntegrationStores(t)
	ctx := context.Background()

	first, err := store.Upsert(ctx, sampleItem())
	if err != nil {
		t.Fatalf("first upsert failed: %v", err)
	}

	second := sampleItem()
	second.SampleEventID = "evt-2"
	again, err := store.Upsert(ctx, second)
	if err != nil {
		t.Fatalf("second upsert failed: %v", err)
	}

	if again.ReviewID != first.ReviewID {
		t.Errorf("expected one row, got ids %d and %d", first.ReviewID, again.ReviewID)
	}
	if again.Occurrences != 2 {
		t.Errorf("expected 2 occurrences, got %d", again.Occurrences)
	}
	if !again.FirstSeenAt.Equal(first.FirstSeenAt) {
		t.Error("expected first_seen_at to be preserved")
	}
	if !again.LastSeenAt.After(first.LastSeenAt) && !again.LastSeenAt.Equal(first.LastSeenAt) {
		t.Error("expected last_seen_at to advance or stay")
	}
	if again.SampleEventID != first.SampleEventID {
		t.Error("expected the first observation to remain the sample evidence")
	}

	items, err := store.List(ctx, Filter{})
	if err != nil {
		t.Fatalf("list failed: %v", err)
	}
	if len(items) != 1 {
		t.Errorf("expected exactly 1 row, got %d", len(items))
	}
}

// TestPostgresStoreConcurrentUpsert — many workers observing the same drift at
// once must converge on one row. This is the concurrency guarantee the design
// rests on: the row identity is computed, not allocated.
func TestPostgresStoreConcurrentUpsert(t *testing.T) {
	store, _, db := newIntegrationStores(t)
	ctx := context.Background()

	const workers = 8
	var wg sync.WaitGroup
	start := make(chan struct{})
	errs := make([]error, workers)
	ids := make([]int64, workers)

	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func(index int) {
			defer wg.Done()
			<-start

			item := sampleItem()
			item.SampleEventID = "evt-concurrent"
			stored, err := store.Upsert(ctx, item)
			if err != nil {
				errs[index] = err
				return
			}
			ids[index] = stored.ReviewID
		}(i)
	}
	close(start)
	wg.Wait()

	for i, err := range errs {
		if err != nil {
			t.Fatalf("worker %d failed: %v", i, err)
		}
	}
	for i, id := range ids {
		if id != ids[0] {
			t.Errorf("worker %d saw review id %d, expected %d", i, id, ids[0])
		}
	}

	var (
		rows        int
		occurrences int
	)
	if err := db.QueryRowContext(ctx,
		`SELECT count(*), COALESCE(MAX(occurrences), 0) FROM source_reviews`).Scan(&rows, &occurrences); err != nil {
		t.Fatalf("failed to count rows: %v", err)
	}
	if rows != 1 {
		t.Errorf("expected 1 row after concurrent upserts, got %d", rows)
	}
	if occurrences != workers {
		t.Errorf("expected %d occurrences, got %d", workers, occurrences)
	}
}

func TestPostgresStoreTransitions(t *testing.T) {
	store, _, _ := newIntegrationStores(t)
	ctx := context.Background()

	item, err := store.Upsert(ctx, sampleItem())
	if err != nil {
		t.Fatalf("upsert failed: %v", err)
	}

	approved, err := store.Decide(ctx, item.ReviewID, Decision{
		Status: StatusApproved, By: "alice", Notes: "looks right", ResultingMappingVersion: 2,
	})
	if err != nil {
		t.Fatalf("approve failed: %v", err)
	}
	if approved.Status != StatusApproved || approved.ResultingMappingVersion != 2 {
		t.Errorf("unexpected approved item: %+v", approved)
	}
	if approved.DecidedAt == nil {
		t.Error("expected decided_at to be set")
	}

	// A second decision must be refused by the compare-and-set.
	if _, err := store.Decide(ctx, item.ReviewID, Decision{Status: StatusRejected, By: "bob"}); !errors.Is(err, ErrInvalidTransition) {
		t.Errorf("expected ErrInvalidTransition, got %v", err)
	}

	reopened, err := store.Reopen(ctx, item.ReviewID, "bob", "reconsidering")
	if err != nil {
		t.Fatalf("reopen failed: %v", err)
	}
	if reopened.Status != StatusPending {
		t.Errorf("expected pending after reopen, got %q", reopened.Status)
	}

	// Reopening a pending item must be refused.
	if _, err := store.Reopen(ctx, item.ReviewID, "bob", ""); !errors.Is(err, ErrInvalidTransition) {
		t.Errorf("expected ErrInvalidTransition, got %v", err)
	}

	if _, err := store.Get(ctx, 999999); !errors.Is(err, ErrNotFound) {
		t.Errorf("expected ErrNotFound, got %v", err)
	}
}

// TestPostgresStoreDecisionSurvivesRecurrence — a rejected drift keeps its
// decision when it happens again, and the recurrence is counted.
func TestPostgresStoreDecisionSurvivesRecurrence(t *testing.T) {
	store, _, _ := newIntegrationStores(t)
	ctx := context.Background()

	item, _ := store.Upsert(ctx, sampleItem())
	if _, err := store.Decide(ctx, item.ReviewID, Decision{Status: StatusRejected, By: "alice", Notes: "expected"}); err != nil {
		t.Fatalf("reject failed: %v", err)
	}

	recurred, err := store.Upsert(ctx, sampleItem())
	if err != nil {
		t.Fatalf("recurring upsert failed: %v", err)
	}
	if recurred.Status != StatusRejected || recurred.DecidedBy != "alice" {
		t.Errorf("expected the rejection to stick, got %q by %q", recurred.Status, recurred.DecidedBy)
	}
	if recurred.Occurrences != 2 {
		t.Errorf("expected 2 occurrences, got %d", recurred.Occurrences)
	}
}

// TestApproveCreatesNewMappingVersion is the core approval guarantee: a new
// append-only version, the old one superseded and unchanged.
func TestApproveCreatesNewMappingVersion(t *testing.T) {
	store, mappings, _ := newIntegrationStores(t)
	ctx := context.Background()

	fingerprint := "fp_approve"
	base := seedMapping(t, mappings, fingerprint)
	baseHash := base.Contract.Hash()

	item := sampleItem()
	item.Fingerprint = fingerprint
	item.MappingID = base.MappingID
	item.MappingVersion = base.MappingVersion
	stored, err := store.Upsert(ctx, item)
	if err != nil {
		t.Fatalf("upsert failed: %v", err)
	}

	// The operator resolves the conflict by declaring the field optional.
	proposed := contract.Contract{Fields: []contract.Field{
		{Name: "timestamp", Type: contract.TypeString, Target: "timestamp", Optional: true},
		{Name: "device_uuid", Type: contract.TypeString, Optional: true},
	}}

	approved, err := Approve(ctx, store, mappings, stored.ReviewID, proposed, "alice", "vendor changed the schema")
	if err != nil {
		t.Fatalf("approve failed: %v", err)
	}
	if approved.Status != StatusApproved {
		t.Errorf("expected approved, got %q", approved.Status)
	}
	if approved.ResultingMappingVersion != 2 {
		t.Fatalf("expected v2 to be activated, got v%d", approved.ResultingMappingVersion)
	}

	// The previous version is intact and superseded.
	old, err := mappings.GetVersion(ctx, registry.VersionRef{
		Fingerprint: fingerprint, MappingID: base.MappingID, MappingVersion: 1,
	})
	if err != nil {
		t.Fatalf("expected v1 to remain: %v", err)
	}
	if old.Status != registry.StatusSuperseded {
		t.Errorf("expected v1 superseded, got %q", old.Status)
	}
	if old.Contract.Hash() != baseHash {
		t.Error("v1's contract was mutated by the approval")
	}

	// The new contract is active and is the one that was proposed.
	active, err := mappings.ActiveFor(ctx, fingerprint)
	if err != nil {
		t.Fatalf("failed to read the active mapping: %v", err)
	}
	if active.MappingVersion != 2 {
		t.Errorf("expected v2 active, got v%d", active.MappingVersion)
	}
	if active.Contract.Hash() != proposed.Normalized().Hash() {
		t.Error("expected the approved contract to be active")
	}
	if active.ParentVersion != 1 {
		t.Errorf("expected the new version to record its parent, got %d", active.ParentVersion)
	}
	if _, ok := active.Contract.Lookup("device_uuid"); !ok {
		t.Error("expected the approved field to be present")
	}
}

// TestApproveIsSafeToRetry — a crash between activating the mapping and
// recording the decision must not create a second version.
func TestApproveIsSafeToRetry(t *testing.T) {
	store, mappings, db := newIntegrationStores(t)
	ctx := context.Background()

	fingerprint := "fp_approve_retry"
	base := seedMapping(t, mappings, fingerprint)

	item := sampleItem()
	item.Fingerprint = fingerprint
	item.MappingID = base.MappingID
	item.MappingVersion = base.MappingVersion
	stored, _ := store.Upsert(ctx, item)

	proposed := contract.Contract{Fields: []contract.Field{
		{Name: "timestamp", Type: contract.TypeString, Target: "timestamp", Optional: true},
	}}

	// First approval succeeds and decides the item.
	first, err := Approve(ctx, store, mappings, stored.ReviewID, proposed, "alice", "")
	if err != nil {
		t.Fatalf("first approval failed: %v", err)
	}

	// A retry of the same approval is refused by the state machine, and — the
	// point of the test — the registry is untouched by the attempt.
	if _, err := Approve(ctx, store, mappings, stored.ReviewID, proposed, "alice", ""); !errors.Is(err, ErrInvalidTransition) {
		t.Errorf("expected the second approval to be refused, got %v", err)
	}

	// The equivalent of a crash-retry: the same contract submitted again
	// directly to the registry must not add a version.
	again, err := mappings.SaveVersion(ctx, registry.Entry{
		Fingerprint: fingerprint, Format: base.Format, MappingID: base.MappingID,
		ParserID: base.ParserID, ParserVersion: base.ParserVersion, Status: registry.StatusActive,
		Contract: proposed, ParentVersion: base.MappingVersion,
	})
	if err != nil {
		t.Fatalf("registry re-submit failed: %v", err)
	}
	if again.MappingVersion != first.ResultingMappingVersion {
		t.Errorf("expected the identical contract to reuse v%d, got v%d",
			first.ResultingMappingVersion, again.MappingVersion)
	}

	var rows int
	if err := db.QueryRowContext(ctx,
		`SELECT count(*) FROM source_registry WHERE fingerprint = $1`, fingerprint).Scan(&rows); err != nil {
		t.Fatalf("failed to count versions: %v", err)
	}
	if rows != 2 {
		t.Errorf("expected exactly 2 mapping versions, got %d", rows)
	}
}

// TestRejectLeavesRegistryUnchanged — rejection is a decision about the queue,
// not about the registry.
func TestRejectLeavesRegistryUnchanged(t *testing.T) {
	store, mappings, db := newIntegrationStores(t)
	ctx := context.Background()

	fingerprint := "fp_reject"
	base := seedMapping(t, mappings, fingerprint)

	item := sampleItem()
	item.Fingerprint = fingerprint
	item.MappingID = base.MappingID
	item.MappingVersion = base.MappingVersion
	stored, _ := store.Upsert(ctx, item)

	rejected, err := Reject(ctx, store, stored.ReviewID, "alice", "the source will be fixed upstream")
	if err != nil {
		t.Fatalf("reject failed: %v", err)
	}
	if rejected.Status != StatusRejected || rejected.DecidedBy != "alice" {
		t.Errorf("unexpected rejected item: %+v", rejected)
	}
	if rejected.ResultingMappingVersion != 0 {
		t.Error("expected no mapping version to result from a rejection")
	}

	// The registry is byte-identical: one version, still active, same contract.
	var rows int
	if err := db.QueryRowContext(ctx,
		`SELECT count(*) FROM source_registry WHERE fingerprint = $1`, fingerprint).Scan(&rows); err != nil {
		t.Fatalf("failed to count versions: %v", err)
	}
	if rows != 1 {
		t.Errorf("expected the registry to be untouched, got %d versions", rows)
	}

	active, err := mappings.ActiveFor(ctx, fingerprint)
	if err != nil {
		t.Fatalf("failed to read the active mapping: %v", err)
	}
	if active.MappingVersion != 1 || active.Contract.Hash() != base.Contract.Hash() {
		t.Error("expected the original mapping to stay active and unchanged")
	}
}

// TestApproveRefusesUnmappedSourcePostgres — the refusal holds at the database
// layer too, where a contract would otherwise be written.
func TestApproveRefusesUnmappedSourcePostgres(t *testing.T) {
	store, mappings, db := newIntegrationStores(t)
	ctx := context.Background()

	item := sampleItem()
	item.Category = CategoryUnmappedSource
	item.MappingID = ""
	item.MappingVersion = 0
	stored, err := store.Upsert(ctx, item)
	if err != nil {
		t.Fatalf("upsert failed: %v", err)
	}

	proposed := contract.Contract{Fields: []contract.Field{
		{Name: "action", Type: contract.TypeString, Target: "event.action"},
	}}
	if _, err := Approve(ctx, store, mappings, stored.ReviewID, proposed, "alice", ""); !errors.Is(err, ErrUnmappedSource) {
		t.Errorf("expected ErrUnmappedSource, got %v", err)
	}

	var rows int
	if err := db.QueryRowContext(ctx, `SELECT count(*) FROM source_registry`).Scan(&rows); err != nil {
		t.Fatalf("failed to count versions: %v", err)
	}
	if rows != 0 {
		t.Errorf("expected no mapping to be written, got %d", rows)
	}
}

func TestPostgresStoreListFilters(t *testing.T) {
	store, _, _ := newIntegrationStores(t)
	ctx := context.Background()

	first, _ := store.Upsert(ctx, sampleItem())
	other := sampleItem()
	other.Fingerprint = "fp-other"
	second, _ := store.Upsert(ctx, other)
	if _, err := store.Decide(ctx, second.ReviewID, Decision{Status: StatusRejected, By: "alice"}); err != nil {
		t.Fatalf("decide failed: %v", err)
	}

	pending, err := store.List(ctx, Filter{Status: StatusPending})
	if err != nil {
		t.Fatalf("list failed: %v", err)
	}
	if len(pending) != 1 || pending[0].ReviewID != first.ReviewID {
		t.Errorf("expected only the pending item, got %+v", pending)
	}

	bySource, _ := store.List(ctx, Filter{Fingerprint: "fp-other"})
	if len(bySource) != 1 || bySource[0].ReviewID != second.ReviewID {
		t.Errorf("expected the other source's item, got %+v", bySource)
	}

	limited, _ := store.List(ctx, Filter{Limit: 1})
	if len(limited) != 1 {
		t.Errorf("expected the limit to apply, got %d", len(limited))
	}
}
