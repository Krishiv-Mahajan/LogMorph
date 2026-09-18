package worker

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/Krishiv-Mahajan/LogMorph/internal/buffer"
	"github.com/Krishiv-Mahajan/LogMorph/internal/drift"
	"github.com/Krishiv-Mahajan/LogMorph/internal/failure"
	"github.com/Krishiv-Mahajan/LogMorph/internal/models"
	"github.com/Krishiv-Mahajan/LogMorph/internal/registry"
	"github.com/Krishiv-Mahajan/LogMorph/internal/review"
	"github.com/Krishiv-Mahajan/LogMorph/internal/storage/normalized"
	"github.com/Krishiv-Mahajan/LogMorph/internal/storage/quarantine"
	"github.com/Krishiv-Mahajan/LogMorph/internal/storage/raw"
)

// flakyReviewStore wraps a working queue and can be switched into a failing
// mode, simulating an unreachable review store.
type flakyReviewStore struct {
	inner *review.MemoryStore

	mu      sync.Mutex
	failing bool
	calls   int
}

func newFlakyReviewStore() *flakyReviewStore {
	return &flakyReviewStore{inner: review.NewMemoryStore()}
}

func (f *flakyReviewStore) setFailing(failing bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.failing = failing
}

func (f *flakyReviewStore) callCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls
}

func (f *flakyReviewStore) Upsert(ctx context.Context, item review.Item) (*review.Item, error) {
	f.mu.Lock()
	f.calls++
	failing := f.failing
	f.mu.Unlock()

	if failing {
		return nil, fmt.Errorf("review store unavailable: connection refused")
	}
	return f.inner.Upsert(ctx, item)
}

func (f *flakyReviewStore) Get(ctx context.Context, id int64) (*review.Item, error) {
	return f.inner.Get(ctx, id)
}

func (f *flakyReviewStore) List(ctx context.Context, filter review.Filter) ([]review.Item, error) {
	return f.inner.List(ctx, filter)
}

func (f *flakyReviewStore) Decide(ctx context.Context, id int64, d review.Decision) (*review.Item, error) {
	return f.inner.Decide(ctx, id, d)
}

func (f *flakyReviewStore) Reopen(ctx context.Context, id int64, by, notes string) (*review.Item, error) {
	return f.inner.Reopen(ctx, id, by, notes)
}

func (f *flakyReviewStore) Ping(ctx context.Context) error { return f.inner.Ping(ctx) }
func (f *flakyReviewStore) Close() error                   { return nil }

// reviewWorker bundles a worker with the stores its tests assert on.
type reviewWorker struct {
	worker     *Worker
	reviews    review.Store
	normalized *normalized.MemoryStore
	quarantine *quarantine.MemoryStore
	registry   registry.Store
}

func newReviewWorker(t *testing.T, reviewStore review.Store) *reviewWorker {
	t.Helper()

	normalizedStore := normalized.NewMemoryStore()
	quarantineStore := quarantine.NewMemoryStore()
	registryStore := registry.NewMemoryStore()

	w, err := setupTestWorkerWithStores(
		&mockWorkerBuffer{}, raw.NewMemoryRawStore(), buffer.NewMemoryIdempotencyStore(),
		normalizedStore, quarantineStore,
		Config{
			DriftAnalyzer: drift.NewEngine(registryStore, realParserCatalog()),
			ReviewStore:   reviewStore,
		},
	)
	if err != nil {
		t.Fatalf("failed to build worker: %v", err)
	}

	return &reviewWorker{
		worker:     w,
		reviews:    reviewStore,
		normalized: normalizedStore,
		quarantine: quarantineStore,
		registry:   registryStore,
	}
}

// process runs one event through the pipeline.
func (rw *reviewWorker) process(t *testing.T, eventID, format, source, payload string) *PipelineResult {
	t.Helper()

	res, _ := rw.worker.ProcessSingleEvent(context.Background(), models.RawEvent{
		EventID:    eventID,
		ReceivedAt: time.Now().UTC().Format(time.RFC3339),
		Format:     format,
		Source:     source,
		Payload:    payload,
	})
	return res
}

// ── What raises an item ──────────────────────────────────────────────────────

// TestReviewRaisedForUnsafeDrift — a required field disappearing is a decision
// the source needs, and the event's own processing is unaffected.
func TestReviewRaisedForUnsafeDrift(t *testing.T) {
	rw := newReviewWorker(t, review.NewMemoryStore())

	// Establish the source's contract first.
	if res := rw.process(t, "evt-setup", "json", "fw-review", `{"timestamp":"2026-08-28T18:30:12Z"}`); res.Outcome != OutcomeSuccess {
		t.Fatalf("setup event failed: %+v", res.Failure)
	}

	// The required timestamp disappears.
	res := rw.process(t, "evt-escalate", "json", "fw-review", `{"firewall":{"action":"deny"}}`)

	if res.Outcome != OutcomeSuccess {
		t.Fatalf("expected the event to still process, got %q (%v)", res.Outcome, res.Failure)
	}
	if res.Review == nil {
		t.Fatal("expected a review item to be raised")
	}
	if res.Review.Category != review.CategoryMappingConflict {
		t.Errorf("expected a mapping conflict, got %q", res.Review.Category)
	}
	if res.Review.DriftStatus != string(models.DriftStatusMajorDrift) {
		t.Errorf("expected major_drift recorded, got %q", res.Review.DriftStatus)
	}
	if len(res.Review.Changes) == 0 {
		t.Error("expected the observed changes to be recorded")
	}
	if res.Review.SampleEventID != "evt-escalate" {
		t.Errorf("expected the raising event to be the sample, got %q", res.Review.SampleEventID)
	}
	if res.Review.MappingVersion != res.Mapping.MappingVersion {
		t.Error("expected the review to record the mapping version in force")
	}

	// The event itself is unaffected: it parsed, validated and was stored.
	if count, _ := rw.normalized.Count(context.Background()); count != 2 {
		t.Errorf("expected both events to be stored, got %d", count)
	}
}

// TestNoReviewForStableOrMinorDrift — only escalations are queued.
func TestNoReviewForStableOrMinorDrift(t *testing.T) {
	rw := newReviewWorker(t, review.NewMemoryStore())

	if res := rw.process(t, "evt-stable", "json", "fw-quiet", `{"timestamp":"2026-08-28T18:30:12Z"}`); res.Review != nil {
		t.Errorf("expected no review for a stable event, got %+v", res.Review)
	}

	// An additive field is adapted deterministically, so no decision is owed.
	res := rw.process(t, "evt-minor", "json", "fw-quiet", `{"timestamp":"2026-08-28T18:30:12Z","device_uuid":"abc"}`)
	if res.SchemaDrift == nil || res.SchemaDrift.Classification != models.DriftStatusMinorDrift {
		t.Fatalf("expected minor drift, got %+v", res.SchemaDrift)
	}
	if res.Review != nil {
		t.Errorf("expected no review for an adapted event, got %+v", res.Review)
	}

	items, _ := rw.reviews.List(context.Background(), review.Filter{})
	if len(items) != 0 {
		t.Errorf("expected an empty queue, got %d items", len(items))
	}
}

// TestReviewRaisedForUnmappedSource — a format with no contract cannot be
// mapped deterministically, and is queued so the gap is visible.
func TestReviewRaisedForUnmappedSource(t *testing.T) {
	rw := newReviewWorker(t, review.NewMemoryStore())

	res := rw.process(t, "evt-unmapped", "xml", "app-server", "<log><action>deny</action></log>")

	if res.Review == nil {
		t.Fatal("expected a review item for an unmapped source")
	}
	if res.Review.Category != review.CategoryUnmappedSource {
		t.Errorf("expected an unmapped source, got %q", res.Review.Category)
	}
	if res.Review.MappingID != "" || res.Review.MappingVersion != 0 {
		t.Errorf("expected no mapping context, got %s v%d", res.Review.MappingID, res.Review.MappingVersion)
	}
	if res.Review.DriftStatus != string(models.DriftStatusUnknown) {
		t.Errorf("expected unknown drift, got %q", res.Review.DriftStatus)
	}
}

// TestNoReviewForUnobservablePayload — a payload the engine cannot observe at
// all is a per-event data problem, and quarantine already owns it. Nothing about
// a mapping can be decided from a payload that cannot be read.
func TestNoReviewForUnobservablePayload(t *testing.T) {
	rw := newReviewWorker(t, review.NewMemoryStore())

	// The source's contract exists, but this payload cannot be parsed against
	// it, so the engine cannot report what changed.
	res := rw.process(t, "evt-unobservable", "json", "fw-broken", `{"broken": `)

	if res.SchemaDrift == nil || !res.SchemaDrift.EscalationRequired {
		t.Fatalf("expected an escalation for the unobservable payload, got %+v", res.SchemaDrift)
	}
	if res.SchemaDrift.Entry == nil {
		t.Fatal("expected the source's contract to still be resolved")
	}
	if len(res.SchemaDrift.Changes) != 0 {
		t.Fatalf("expected no recorded changes, got %+v", res.SchemaDrift.Changes)
	}
	if res.Review != nil {
		t.Errorf("expected no review item, got %+v", res.Review)
	}
	if res.Outcome != OutcomeQuarantined {
		t.Errorf("expected the event to be quarantined, got %q", res.Outcome)
	}

	items, _ := rw.reviews.List(context.Background(), review.Filter{})
	if len(items) != 0 {
		t.Errorf("expected an empty queue, got %d items", len(items))
	}
}

// TestReviewAndQuarantineAreIndependent — one event can be both a decision owed
// and an event that could not be processed. Neither record references the other,
// and neither is a substitute for the other.
func TestReviewAndQuarantineAreIndependent(t *testing.T) {
	mockBuf := &mockWorkerBuffer{}
	normalizedStore := normalized.NewMemoryStore()
	quarantineStore := quarantine.NewMemoryStore()
	reviewStore := review.NewMemoryStore()

	w, err := setupTestWorkerWithStores(
		mockBuf, raw.NewMemoryRawStore(), buffer.NewMemoryIdempotencyStore(),
		normalizedStore, quarantineStore,
		Config{
			DriftAnalyzer: drift.NewEngine(registry.NewMemoryStore(), realParserCatalog()),
			ReviewStore:   reviewStore,
		},
	)
	if err != nil {
		t.Fatalf("setup: %v", err)
	}

	// Establish the contract: a stable event, so no review is owed.
	setup := models.RawEvent{
		EventID: "evt-setup", Format: "json", Source: "fw-both",
		Payload: `{"timestamp":"2026-08-28T18:30:12Z"}`,
	}
	if res, _ := w.ProcessSingleEvent(context.Background(), setup); res.Outcome != OutcomeSuccess {
		t.Fatalf("setup event failed: %v", res.Failure)
	}

	// The next event drops the required timestamp (an escalation) and carries an
	// out-of-range port (a validation failure).
	mockBuf.mu.Lock()
	mockBuf.messages = []buffer.RawMessage{{
		ID: "msg-both",
		Event: models.RawEvent{
			EventID: "evt-both", Format: "json", Source: "fw-both",
			Payload: `{"src_port":999999}`,
		},
	}}
	mockBuf.mu.Unlock()

	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()
	_ = w.Start(ctx)

	waitFor(t, time.Second, func() bool {
		count, _ := quarantineStore.Count(context.Background())
		return count == 1
	}, "the event to be quarantined")

	// Both records exist.
	items, _ := reviewStore.List(context.Background(), review.Filter{})
	if len(items) != 1 {
		t.Fatalf("expected 1 review item, got %d", len(items))
	}
	entry, err := quarantineStore.Get(context.Background(), "evt-both")
	if err != nil {
		t.Fatalf("expected a quarantine entry: %v", err)
	}
	if entry.Provenance.DriftStatus != string(models.DriftStatusMajorDrift) {
		t.Errorf("expected the quarantine record to carry the drift status, got %q", entry.Provenance.DriftStatus)
	}
	if entry.Provenance.MappingVersion != items[0].MappingVersion {
		t.Error("expected both records to name the same mapping version")
	}
	if items[0].SampleEventID != "evt-both" {
		t.Errorf("expected the review to point at the same event, got %q", items[0].SampleEventID)
	}

	// The quarantine record carries no review reference and vice versa.
	if entry.Type == "" || items[0].Signature == "" {
		t.Error("expected each record to stand on its own")
	}
	if count, _ := normalizedStore.Count(context.Background()); count != 1 {
		t.Errorf("expected only the setup event to be stored, got %d", count)
	}
}

// ── Duplicate drift ──────────────────────────────────────────────────────────

// TestDuplicateDriftProducesOneReviewItem — the queue is bounded by decisions,
// not by events.
func TestDuplicateDriftProducesOneReviewItem(t *testing.T) {
	rw := newReviewWorker(t, review.NewMemoryStore())

	if res := rw.process(t, "evt-setup", "json", "fw-dup", `{"timestamp":"2026-08-28T18:30:12Z"}`); res.Outcome != OutcomeSuccess {
		t.Fatalf("setup failed: %v", res.Failure)
	}

	const events = 5
	for i := 0; i < events; i++ {
		res := rw.process(t, fmt.Sprintf("evt-dup-%d", i), "json", "fw-dup", `{"firewall":{"action":"deny"}}`)
		if res.Outcome != OutcomeSuccess {
			t.Fatalf("event %d failed: %v", i, res.Failure)
		}
	}

	items, err := rw.reviews.List(context.Background(), review.Filter{})
	if err != nil {
		t.Fatalf("list failed: %v", err)
	}
	if len(items) != 1 {
		t.Fatalf("expected exactly 1 review item for %d identical events, got %d", events, len(items))
	}
	if items[0].Occurrences != events {
		t.Errorf("expected %d occurrences, got %d", events, items[0].Occurrences)
	}
}

// ── Review persistence failure is retryable ──────────────────────────────────

// TestReviewPersistenceFailureIsRetryable — the escalation signal must never be
// lost: either the item is durable, or the event is retried.
func TestReviewPersistenceFailureIsRetryable(t *testing.T) {
	store := newFlakyReviewStore()
	store.setFailing(true)
	rw := newReviewWorker(t, store)

	if res := rw.process(t, "evt-setup", "json", "fw-retry", `{"timestamp":"2026-08-28T18:30:12Z"}`); res.Outcome != OutcomeSuccess {
		t.Fatalf("setup failed: %v", res.Failure)
	}

	res := rw.process(t, "evt-retry", "json", "fw-retry", `{"firewall":{"action":"deny"}}`)

	if res.Outcome != OutcomeRetryableFailure {
		t.Fatalf("expected a retryable failure, got %q", res.Outcome)
	}
	if res.Failure == nil || res.Failure.Stage != failure.StageReview || res.Failure.TypeCode() != failure.TypeReviewFailed {
		t.Fatalf("expected the failure to be attributed to the review stage, got %+v", res.Failure)
	}
	if res.Review != nil {
		t.Error("expected no review item on the result when persistence failed")
	}
	// Nothing was persisted for this event, so a retry starts clean.
	if _, err := rw.normalized.Get(context.Background(), "evt-retry"); err == nil {
		t.Error("expected no normalized record for the failed attempt")
	}
	if _, err := rw.quarantine.Get(context.Background(), "evt-retry"); err == nil {
		t.Error("expected no quarantine record for the failed attempt")
	}
	if store.callCount() == 0 {
		t.Error("expected the review write to have been attempted")
	}
}

// TestReviewRetrySucceedsAfterRecovery — once the store is back, the same event
// queues exactly one item and then finishes normally.
func TestReviewRetrySucceedsAfterRecovery(t *testing.T) {
	store := newFlakyReviewStore()
	store.setFailing(true)
	rw := newReviewWorker(t, store)

	if res := rw.process(t, "evt-setup", "json", "fw-recover", `{"timestamp":"2026-08-28T18:30:12Z"}`); res.Outcome != OutcomeSuccess {
		t.Fatalf("setup failed: %v", res.Failure)
	}

	const payload = `{"firewall":{"action":"deny"}}`
	if res := rw.process(t, "evt-recover", "json", "fw-recover", payload); res.Outcome != OutcomeRetryableFailure {
		t.Fatalf("expected the first attempt to be retryable, got %q", res.Outcome)
	}

	store.setFailing(false)

	res := rw.process(t, "evt-recover", "json", "fw-recover", payload)
	if res.Outcome != OutcomeSuccess {
		t.Fatalf("expected the retry to succeed, got %q (%v)", res.Outcome, res.Failure)
	}
	if res.Review == nil {
		t.Fatal("expected the retry to queue the review")
	}

	items, _ := rw.reviews.List(context.Background(), review.Filter{})
	if len(items) != 1 {
		t.Fatalf("expected exactly 1 review item after the retry, got %d", len(items))
	}
	if items[0].Occurrences != 1 {
		t.Errorf("expected the failed attempt not to be counted, got %d occurrences", items[0].Occurrences)
	}
}

// TestReviewStoreOutageDoesNotAffectHealthyTraffic — the blast radius of a
// review-store failure is escalation traffic only.
func TestReviewStoreOutageDoesNotAffectHealthyTraffic(t *testing.T) {
	store := newFlakyReviewStore()
	store.setFailing(true)
	rw := newReviewWorker(t, store)

	stable := rw.process(t, "evt-stable", "json", "fw-healthy", `{"timestamp":"2026-08-28T18:30:12Z"}`)
	if stable.Outcome != OutcomeSuccess {
		t.Errorf("expected a stable event to be unaffected, got %q", stable.Outcome)
	}

	minor := rw.process(t, "evt-minor", "json", "fw-healthy", `{"timestamp":"2026-08-28T18:30:12Z","device_uuid":"abc"}`)
	if minor.Outcome != OutcomeSuccess {
		t.Errorf("expected a minor drift event to be unaffected, got %q", minor.Outcome)
	}

	if store.callCount() != 0 {
		t.Errorf("expected no review write for non-escalating events, got %d", store.callCount())
	}
}

// TestWorkerWithoutReviewStoreIsUnchanged — the queue is opt-in, so every
// existing deployment keeps working untouched.
func TestWorkerWithoutReviewStoreIsUnchanged(t *testing.T) {
	rw := newReviewWorker(t, nil)

	res := rw.process(t, "evt-nostore", "json", "fw-nostore", `{"firewall":{"action":"deny"}}`)

	if res.Outcome != OutcomeSuccess {
		t.Fatalf("expected the event to process, got %q (%v)", res.Outcome, res.Failure)
	}
	if res.Review != nil {
		t.Errorf("expected no review item, got %+v", res.Review)
	}
	// The escalation is still visible in provenance and the drift verdict.
	if res.Provenance.DriftStatus != string(models.DriftStatusMajorDrift) {
		t.Errorf("expected the drift signal in provenance, got %q", res.Provenance.DriftStatus)
	}
}

// TestReviewPersistenceFailureDoesNotAck — the retry is the worker's existing
// one: the message is left in the pending list rather than being acknowledged
// and lost.
func TestReviewPersistenceFailureDoesNotAck(t *testing.T) {
	store := newFlakyReviewStore()
	store.setFailing(true)

	mockBuf := &mockWorkerBuffer{}
	w, err := setupTestWorkerWithStores(
		mockBuf, raw.NewMemoryRawStore(), buffer.NewMemoryIdempotencyStore(),
		normalized.NewMemoryStore(), quarantine.NewMemoryStore(),
		Config{
			DriftAnalyzer: drift.NewEngine(registry.NewMemoryStore(), realParserCatalog()),
			ReviewStore:   store,
		},
	)
	if err != nil {
		t.Fatalf("setup: %v", err)
	}

	// Establish the source's contract with a stable event: no review write is
	// attempted, so it succeeds while the store is down.
	setup := models.RawEvent{
		EventID: "evt-ack-setup", Format: "json", Source: "fw-ack",
		Payload: `{"timestamp":"2026-08-28T18:30:12Z"}`,
	}
	if res, _ := w.ProcessSingleEvent(context.Background(), setup); res.Outcome != OutcomeSuccess {
		t.Fatalf("setup event failed: %v", res.Failure)
	}

	// Queue the escalating event for the consumer loop.
	mockBuf.mu.Lock()
	mockBuf.messages = []buffer.RawMessage{{
		ID: "msg-review-fail",
		Event: models.RawEvent{
			EventID: "evt-ack", Format: "json", Source: "fw-ack",
			Payload: `{"firewall":{"action":"deny"}}`,
		},
	}}
	mockBuf.mu.Unlock()

	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()
	_ = w.Start(ctx)

	waitFor(t, time.Second, func() bool { return store.callCount() > 0 }, "the review write to be attempted")

	mockBuf.mu.Lock()
	acked := append([]string(nil), mockBuf.acked...)
	mockBuf.mu.Unlock()

	if len(acked) != 0 {
		t.Errorf("expected NO ACK when the review could not be persisted, got %v", acked)
	}
}
