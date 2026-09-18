package worker

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/Krishiv-Mahajan/LogMorph/internal/buffer"
	"github.com/Krishiv-Mahajan/LogMorph/internal/failure"
	"github.com/Krishiv-Mahajan/LogMorph/internal/models"
	"github.com/Krishiv-Mahajan/LogMorph/internal/storage/normalized"
	"github.com/Krishiv-Mahajan/LogMorph/internal/storage/quarantine"
	"github.com/Krishiv-Mahajan/LogMorph/internal/storage/raw"
)

// ── Test doubles ─────────────────────────────────────────────────────────────

// flakyNormalizedStore wraps a working store and can be switched into a failing
// mode, simulating a PostgreSQL outage.
type flakyNormalizedStore struct {
	inner *normalized.MemoryStore

	mu      sync.Mutex
	failing bool
	calls   int
}

func newFlakyNormalizedStore() *flakyNormalizedStore {
	return &flakyNormalizedStore{inner: normalized.NewMemoryStore()}
}

func (f *flakyNormalizedStore) setFailing(failing bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.failing = failing
}

func (f *flakyNormalizedStore) callCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls
}

func (f *flakyNormalizedStore) Save(ctx context.Context, rec normalized.Record) (bool, error) {
	f.mu.Lock()
	f.calls++
	failing := f.failing
	f.mu.Unlock()

	if failing {
		return false, fmt.Errorf("database unavailable: connection refused")
	}
	return f.inner.Save(ctx, rec)
}

func (f *flakyNormalizedStore) Get(ctx context.Context, eventID string) (*normalized.Record, error) {
	return f.inner.Get(ctx, eventID)
}

func (f *flakyNormalizedStore) Count(ctx context.Context) (int64, error) {
	return f.inner.Count(ctx)
}

func (f *flakyNormalizedStore) Ping(ctx context.Context) error { return f.inner.Ping(ctx) }
func (f *flakyNormalizedStore) Close() error                   { return nil }

// flakyRawStore simulates a MinIO outage for the immutable raw copy.
type flakyRawStore struct {
	inner *raw.MemoryRawStore

	mu      sync.Mutex
	failing bool
}

func newFlakyRawStore() *flakyRawStore {
	return &flakyRawStore{inner: raw.NewMemoryRawStore()}
}

func (f *flakyRawStore) setFailing(failing bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.failing = failing
}

func (f *flakyRawStore) Put(ctx context.Context, event *models.RawEvent) error {
	f.mu.Lock()
	failing := f.failing
	f.mu.Unlock()

	if failing {
		return fmt.Errorf("minio unavailable: connection refused")
	}
	return f.inner.Put(ctx, event)
}

func (f *flakyRawStore) Get(ctx context.Context, eventID string) (*models.RawEvent, error) {
	return f.inner.Get(ctx, eventID)
}

func (f *flakyRawStore) Close() error { return nil }

// ── Helpers ──────────────────────────────────────────────────────────────────

// jsonMsg builds a JSON raw message with the given payload.
func jsonMsg(id, eventID, payload string) buffer.RawMessage {
	return buffer.RawMessage{
		ID: id,
		Event: models.RawEvent{
			EventID:    eventID,
			ReceivedAt: time.Now().UTC().Format(time.RFC3339),
			Format:     "json",
			Source:     "firewall-01",
			Payload:    payload,
		},
	}
}

const validJSONPayload = `{"timestamp":"2026-08-28T18:30:12Z","firewall":{"action":"deny","protocol":"TCP"},` +
	`"network":{"source":{"ip":"192.168.1.20","port":54321},"destination":{"ip":"10.0.0.15","port":443}}}`

// invalidJSONPayload parses and normalizes cleanly but violates the Universal
// Event schema: src_port 999999 exceeds the maximum of 65535.
const invalidJSONPayload = `{"timestamp":"2026-08-28T18:30:12Z","firewall":{"action":"deny","protocol":"TCP"},` +
	`"src_ip":"192.168.1.20","src_port":999999}`

// ── SUCCESS ──────────────────────────────────────────────────────────────────

// TestOutcome_SuccessPersistsNormalizedEvent walks the full happy path and
// verifies the normalized record, the MinIO reference, and the ACK.
func TestOutcome_SuccessPersistsNormalizedEvent(t *testing.T) {
	msg := jsonMsg("msg-ok", "evt_ok", validJSONPayload)

	mockBuf := &mockWorkerBuffer{messages: []buffer.RawMessage{msg}}
	rawStore := raw.NewMemoryRawStore()
	normalizedStore := normalized.NewMemoryStore()
	quarantineStore := quarantine.NewMemoryStore()
	idempotency := buffer.NewMemoryIdempotencyStore()

	w, err := setupTestWorkerWithStores(mockBuf, rawStore, idempotency, normalizedStore, quarantineStore, Config{})
	if err != nil {
		t.Fatalf("setup: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 400*time.Millisecond)
	defer cancel()
	_ = w.Start(ctx)

	waitFor(t, time.Second, func() bool {
		count, _ := normalizedStore.Count(context.Background())
		return count == 1
	}, "the normalized event to be persisted")

	// ACK + done marker.
	if len(mockBuf.acked) != 1 || mockBuf.acked[0] != "msg-ok" {
		t.Errorf("expected msg-ok to be ACKed, got %v", mockBuf.acked)
	}
	done, _ := idempotency.IsDone(context.Background(), "evt_ok")
	if !done {
		t.Errorf("expected evt_ok to be marked done")
	}

	// The immutable raw copy is still written to the raw store.
	storedRaw, err := rawStore.Get(context.Background(), "evt_ok")
	if err != nil {
		t.Fatalf("expected raw event in raw store: %v", err)
	}
	if storedRaw.Payload != validJSONPayload {
		t.Errorf("raw payload mismatch: %s", storedRaw.Payload)
	}

	// The normalized record references the raw object instead of copying it.
	rec, err := normalizedStore.Get(context.Background(), "evt_ok")
	if err != nil {
		t.Fatalf("expected normalized event: %v", err)
	}
	if rec.RawObjectKey != raw.ObjectKey("evt_ok") {
		t.Errorf("expected raw object key %q, got %q", raw.ObjectKey("evt_ok"), rec.RawObjectKey)
	}
	if rec.Event.SchemaVersion != "1.0" {
		t.Errorf("expected schema version 1.0, got %q", rec.Event.SchemaVersion)
	}
	if rec.Event.Event.Action != "deny" {
		t.Errorf("expected action deny, got %q", rec.Event.Event.Action)
	}
	if rec.Event.Network == nil || rec.Event.Network.SrcIP != "192.168.1.20" {
		t.Errorf("expected normalized network info, got %+v", rec.Event.Network)
	}

	// Nothing may be quarantined on the happy path.
	if count, _ := quarantineStore.Count(context.Background()); count != 0 {
		t.Errorf("expected nothing quarantined, got %d", count)
	}
}

// ── PARSE FAILURE ────────────────────────────────────────────────────────────

// TestOutcome_ParseFailureQuarantinesAndACKs — malformed input with a known
// format hint is a permanent failure: quarantine, ACK, no normalized record.
func TestOutcome_ParseFailureQuarantinesAndACKs(t *testing.T) {
	msg := jsonMsg("msg-bad-json", "evt_bad_json", `{"broken": `)

	mockBuf := &mockWorkerBuffer{messages: []buffer.RawMessage{msg}}
	normalizedStore := normalized.NewMemoryStore()
	quarantineStore := quarantine.NewMemoryStore()

	w, err := setupTestWorkerWithStores(
		mockBuf, raw.NewMemoryRawStore(), buffer.NewMemoryIdempotencyStore(),
		normalizedStore, quarantineStore, Config{},
	)
	if err != nil {
		t.Fatalf("setup: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 400*time.Millisecond)
	defer cancel()
	_ = w.Start(ctx)

	waitFor(t, time.Second, func() bool {
		count, _ := quarantineStore.Count(context.Background())
		return count == 1
	}, "the malformed event to be quarantined")

	if len(mockBuf.acked) != 1 {
		t.Errorf("expected the quarantined message to be ACKed, got %v", mockBuf.acked)
	}

	entry, err := quarantineStore.Get(context.Background(), "evt_bad_json")
	if err != nil {
		t.Fatalf("expected quarantine entry: %v", err)
	}
	if entry.Stage != string(failure.StageParsing) {
		t.Errorf("expected stage %q, got %q", failure.StageParsing, entry.Stage)
	}
	if entry.Type != failure.TypeParseFailed {
		t.Errorf("expected type %q, got %q", failure.TypeParseFailed, entry.Type)
	}
	if entry.Message == "" {
		t.Error("expected a non-empty error message on the quarantine entry")
	}
	if entry.QuarantinedAt.IsZero() {
		t.Error("expected a quarantine timestamp")
	}
	if count, _ := normalizedStore.Count(context.Background()); count != 0 {
		t.Errorf("expected no normalized records, got %d", count)
	}
}

// ── VALIDATION FAILURE ───────────────────────────────────────────────────────

// TestOutcome_ValidationFailureQuarantinesAndACKs — an event that parses and
// normalizes but violates the JSON schema must be quarantined, not dropped.
func TestOutcome_ValidationFailureQuarantinesAndACKs(t *testing.T) {
	msg := jsonMsg("msg-invalid", "evt_invalid", invalidJSONPayload)

	mockBuf := &mockWorkerBuffer{messages: []buffer.RawMessage{msg}}
	normalizedStore := normalized.NewMemoryStore()
	quarantineStore := quarantine.NewMemoryStore()

	w, err := setupTestWorkerWithStores(
		mockBuf, raw.NewMemoryRawStore(), buffer.NewMemoryIdempotencyStore(),
		normalizedStore, quarantineStore, Config{},
	)
	if err != nil {
		t.Fatalf("setup: %v", err)
	}

	// Direct call first: the outcome must be explicit and the validation
	// details must be preserved.
	res, err := w.ProcessSingleEvent(context.Background(), msg.Event)
	if err == nil {
		t.Fatal("expected an error for a schema-invalid event")
	}
	if res.Outcome != OutcomeQuarantined {
		t.Errorf("expected outcome %q, got %q", OutcomeQuarantined, res.Outcome)
	}
	if res.Valid {
		t.Error("expected Valid=false")
	}
	if len(res.Errors) == 0 {
		t.Error("expected validation errors on the result")
	}
	if res.Failure.Stage != failure.StageValidation {
		t.Errorf("expected stage %q, got %q", failure.StageValidation, res.Failure.Stage)
	}
	if res.Failure.Type != failure.TypeValidationFailed {
		t.Errorf("expected type %q, got %q", failure.TypeValidationFailed, res.Failure.Type)
	}

	// Then through the worker loop: quarantine + ACK.
	ctx, cancel := context.WithTimeout(context.Background(), 400*time.Millisecond)
	defer cancel()
	_ = w.Start(ctx)

	waitFor(t, time.Second, func() bool {
		count, _ := quarantineStore.Count(context.Background())
		return count == 1
	}, "the schema-invalid event to be quarantined")

	if len(mockBuf.acked) != 1 {
		t.Errorf("expected the quarantined message to be ACKed, got %v", mockBuf.acked)
	}

	entry, err := quarantineStore.Get(context.Background(), "evt_invalid")
	if err != nil {
		t.Fatalf("expected quarantine entry: %v", err)
	}
	if entry.Stage != string(failure.StageValidation) {
		t.Errorf("expected stage %q, got %q", failure.StageValidation, entry.Stage)
	}
	if entry.Message == "" {
		t.Error("expected the validation failure reason to be recorded")
	}
	if count, _ := normalizedStore.Count(context.Background()); count != 0 {
		t.Errorf("expected no normalized records for an invalid event, got %d", count)
	}
}

// ── DUPLICATE ────────────────────────────────────────────────────────────────

// TestOutcome_DuplicateDeliveryWritesSingleNormalizedRecord — the same event
// delivered twice must produce exactly one normalized record.
func TestOutcome_DuplicateDeliveryWritesSingleNormalizedRecord(t *testing.T) {
	rawStore := raw.NewMemoryRawStore()
	normalizedStore := normalized.NewMemoryStore()
	quarantineStore := quarantine.NewMemoryStore()
	idempotency := buffer.NewMemoryIdempotencyStore()

	// Two deliveries of the same event_id, with different stream message ids.
	buf1 := &mockWorkerBuffer{messages: []buffer.RawMessage{jsonMsg("msg-a", "evt_dup", validJSONPayload)}}
	w1, err := setupTestWorkerWithStores(buf1, rawStore, idempotency, normalizedStore, quarantineStore, Config{})
	if err != nil {
		t.Fatalf("setup w1: %v", err)
	}

	ctx1, cancel1 := context.WithTimeout(context.Background(), 400*time.Millisecond)
	defer cancel1()
	_ = w1.Start(ctx1)

	waitFor(t, time.Second, func() bool {
		count, _ := normalizedStore.Count(context.Background())
		return count == 1
	}, "the first delivery to be persisted")

	buf2 := &mockWorkerBuffer{messages: []buffer.RawMessage{jsonMsg("msg-b", "evt_dup", validJSONPayload)}}
	w2, err := setupTestWorkerWithStores(buf2, rawStore, idempotency, normalizedStore, quarantineStore, Config{})
	if err != nil {
		t.Fatalf("setup w2: %v", err)
	}

	ctx2, cancel2 := context.WithTimeout(context.Background(), 400*time.Millisecond)
	defer cancel2()
	_ = w2.Start(ctx2)

	// The duplicate takes the IsDone fast path and is ACKed to clear the PEL.
	waitFor(t, time.Second, func() bool {
		buf2.mu.Lock()
		defer buf2.mu.Unlock()
		return len(buf2.acked) == 1
	}, "the duplicate delivery to be ACKed")

	if count, _ := normalizedStore.Count(context.Background()); count != 1 {
		t.Errorf("expected exactly 1 normalized record, got %d", count)
	}
	if count, _ := quarantineStore.Count(context.Background()); count != 0 {
		t.Errorf("expected no quarantine entries, got %d", count)
	}

	// Store-level idempotency, independent of the Redis done-marker: saving the
	// same event again must not insert a second row.
	inserted, err := normalizedStore.Save(context.Background(), normalized.Record{
		Event:        mustNormalize(t, w1, validJSONPayload),
		RawObjectKey: raw.ObjectKey("evt_dup"),
	})
	if err != nil {
		t.Fatalf("second save failed: %v", err)
	}
	if inserted {
		t.Error("expected the second save of the same event_id to be ignored")
	}
	if count, _ := normalizedStore.Count(context.Background()); count != 1 {
		t.Errorf("expected exactly 1 normalized record after a duplicate save, got %d", count)
	}
}

// mustNormalize runs the pipeline and returns the normalized event.
func mustNormalize(t *testing.T, w *Worker, payload string) *models.UniversalEvent {
	t.Helper()

	res, err := w.ProcessSingleEvent(context.Background(), models.RawEvent{
		EventID:    "evt_dup",
		ReceivedAt: time.Now().UTC().Format(time.RFC3339),
		Format:     "json",
		Source:     "firewall-01",
		Payload:    payload,
	})
	if err != nil {
		t.Fatalf("pipeline failed: %v", err)
	}
	return res.UniversalEvent
}

// ── RETRYABLE FAILURES ───────────────────────────────────────────────────────

// TestOutcome_RetryablePersistenceFailureIsNotQuarantined — while PostgreSQL is
// down the event must stay retryable: no ACK, no quarantine entry. Once the
// database recovers the same event is processed successfully.
func TestOutcome_RetryablePersistenceFailureIsNotQuarantined(t *testing.T) {
	rawStore := raw.NewMemoryRawStore()
	normalizedStore := newFlakyNormalizedStore()
	quarantineStore := quarantine.NewMemoryStore()
	idempotency := buffer.NewMemoryIdempotencyStore()

	normalizedStore.setFailing(true)

	buf1 := &mockWorkerBuffer{messages: []buffer.RawMessage{jsonMsg("msg-retry", "evt_retry", validJSONPayload)}}
	w1, err := setupTestWorkerWithStores(buf1, rawStore, idempotency, normalizedStore, quarantineStore, Config{})
	if err != nil {
		t.Fatalf("setup w1: %v", err)
	}

	ctx1, cancel1 := context.WithTimeout(context.Background(), 400*time.Millisecond)
	defer cancel1()
	_ = w1.Start(ctx1)

	waitFor(t, time.Second, func() bool { return normalizedStore.callCount() >= 1 },
		"the persistence attempt to happen")

	if count, _ := quarantineStore.Count(context.Background()); count != 0 {
		t.Errorf("a temporary database outage must not quarantine events, got %d entries", count)
	}
	if len(buf1.acked) != 0 {
		t.Errorf("expected NO ACK while the database is down, got %v", buf1.acked)
	}

	// The processing lock must be released so the retry can claim the event.
	waitFor(t, time.Second, func() bool {
		done, _ := idempotency.IsDone(context.Background(), "evt_retry")
		return !done
	}, "the event to remain unprocessed")

	// Recovery: the database comes back and the redelivered event succeeds.
	normalizedStore.setFailing(false)

	buf2 := &mockWorkerBuffer{messages: []buffer.RawMessage{jsonMsg("msg-retry-2", "evt_retry", validJSONPayload)}}
	w2, err := setupTestWorkerWithStores(buf2, rawStore, idempotency, normalizedStore, quarantineStore, Config{})
	if err != nil {
		t.Fatalf("setup w2: %v", err)
	}

	ctx2, cancel2 := context.WithTimeout(context.Background(), 400*time.Millisecond)
	defer cancel2()
	_ = w2.Start(ctx2)

	waitFor(t, time.Second, func() bool {
		count, _ := normalizedStore.Count(context.Background())
		return count == 1
	}, "the event to be persisted after recovery")

	if len(buf2.acked) != 1 {
		t.Errorf("expected the retried message to be ACKed after recovery, got %v", buf2.acked)
	}
	if count, _ := quarantineStore.Count(context.Background()); count != 0 {
		t.Errorf("expected no quarantine entries after recovery, got %d", count)
	}
}

// TestOutcome_RawStoreFailureIsRetryable — a MinIO outage must not quarantine
// the event: without the immutable raw object the normalized record would
// reference a payload that does not exist.
func TestOutcome_RawStoreFailureIsRetryable(t *testing.T) {
	rawStore := newFlakyRawStore()
	rawStore.setFailing(true)

	normalizedStore := normalized.NewMemoryStore()
	quarantineStore := quarantine.NewMemoryStore()

	w, err := setupTestWorkerWithStores(
		&mockWorkerBuffer{}, rawStore, buffer.NewMemoryIdempotencyStore(),
		normalizedStore, quarantineStore, Config{},
	)
	if err != nil {
		t.Fatalf("setup: %v", err)
	}

	res, err := w.ProcessSingleEvent(context.Background(), jsonMsg("m", "evt_minio", validJSONPayload).Event)
	if err == nil {
		t.Fatal("expected an error when the raw store is unavailable")
	}
	if res.Outcome != OutcomeRetryableFailure {
		t.Errorf("expected outcome %q, got %q", OutcomeRetryableFailure, res.Outcome)
	}
	if res.Failure.Stage != failure.StageRawStore {
		t.Errorf("expected stage %q, got %q", failure.StageRawStore, res.Failure.Stage)
	}
	if !failure.IsRetryable(err) {
		t.Error("expected the raw store failure to be retryable")
	}
	if count, _ := normalizedStore.Count(context.Background()); count != 0 {
		t.Errorf("expected no normalized records while the raw store is down, got %d", count)
	}
}

// TestOutcome_MaxAttemptsEscalatesToQuarantine — a retryable failure that
// outlives the attempt budget is quarantined instead of being retried forever.
func TestOutcome_MaxAttemptsEscalatesToQuarantine(t *testing.T) {
	rawStore := raw.NewMemoryRawStore()
	normalizedStore := newFlakyNormalizedStore()
	quarantineStore := quarantine.NewMemoryStore()
	idempotency := buffer.NewMemoryIdempotencyStore()

	normalizedStore.setFailing(true)

	const maxAttempts = 2
	cfg := Config{MaxAttempts: maxAttempts}

	// Attempt 1 — still within budget: retryable, not quarantined.
	buf1 := &mockWorkerBuffer{messages: []buffer.RawMessage{jsonMsg("msg-1", "evt_cap", validJSONPayload)}}
	w1, err := setupTestWorkerWithStores(buf1, rawStore, idempotency, normalizedStore, quarantineStore, cfg)
	if err != nil {
		t.Fatalf("setup w1: %v", err)
	}

	ctx1, cancel1 := context.WithTimeout(context.Background(), 400*time.Millisecond)
	defer cancel1()
	_ = w1.Start(ctx1)

	waitFor(t, time.Second, func() bool { return normalizedStore.callCount() >= 1 },
		"the first persistence attempt")

	if len(buf1.acked) != 0 {
		t.Fatalf("expected no ACK on the first retryable failure, got %v", buf1.acked)
	}
	if count, _ := quarantineStore.Count(context.Background()); count != 0 {
		t.Fatalf("expected no quarantine before the cap is reached, got %d", count)
	}

	// Attempt 2 — the budget is exhausted: quarantine + ACK.
	buf2 := &mockWorkerBuffer{messages: []buffer.RawMessage{jsonMsg("msg-2", "evt_cap", validJSONPayload)}}
	w2, err := setupTestWorkerWithStores(buf2, rawStore, idempotency, normalizedStore, quarantineStore, cfg)
	if err != nil {
		t.Fatalf("setup w2: %v", err)
	}

	ctx2, cancel2 := context.WithTimeout(context.Background(), 400*time.Millisecond)
	defer cancel2()
	_ = w2.Start(ctx2)

	waitFor(t, time.Second, func() bool {
		count, _ := quarantineStore.Count(context.Background())
		return count == 1
	}, "the event to be quarantined once the attempt cap is reached")

	if len(buf2.acked) != 1 {
		t.Errorf("expected the escalated message to be ACKed, got %v", buf2.acked)
	}

	entry, err := quarantineStore.Get(context.Background(), "evt_cap")
	if err != nil {
		t.Fatalf("expected quarantine entry: %v", err)
	}
	if entry.Type != failure.TypeMaxAttempts {
		t.Errorf("expected failure type %q, got %q", failure.TypeMaxAttempts, entry.Type)
	}
	if entry.Stage != string(failure.StagePersistence) {
		t.Errorf("expected the original stage %q to be preserved, got %q", failure.StagePersistence, entry.Stage)
	}
	if entry.Attempts < maxAttempts {
		t.Errorf("expected at least %d attempts recorded, got %d", maxAttempts, entry.Attempts)
	}
}

// TestOutcome_GenuinePermanentFailureIgnoresAttemptBudget — a deterministic
// failure is quarantined on the first attempt, however generous the budget is.
func TestOutcome_GenuinePermanentFailureIgnoresAttemptBudget(t *testing.T) {
	quarantineStore := quarantine.NewMemoryStore()

	w, err := setupTestWorkerWithStores(
		&mockWorkerBuffer{}, raw.NewMemoryRawStore(), buffer.NewMemoryIdempotencyStore(),
		normalized.NewMemoryStore(), quarantineStore, Config{MaxAttempts: 100},
	)
	if err != nil {
		t.Fatalf("setup: %v", err)
	}

	res, _ := w.ProcessSingleEvent(context.Background(), jsonMsg("m", "evt_perm", invalidJSONPayload).Event)
	if res.Outcome != OutcomeQuarantined {
		t.Errorf("expected an immediate quarantine, got outcome %q", res.Outcome)
	}
	if res.Failure.Class != failure.ClassPermanent {
		t.Errorf("expected class %q, got %q", failure.ClassPermanent, res.Failure.Class)
	}
}

// ── POISON PILL ──────────────────────────────────────────────────────────────

// TestOutcome_PoisonPillDoesNotBlockSubsequentEvents — a permanently failing
// event in the middle of a batch must not stop the healthy events behind it.
func TestOutcome_PoisonPillDoesNotBlockSubsequentEvents(t *testing.T) {
	messages := []buffer.RawMessage{
		jsonMsg("msg-poison", "evt_poison", `{"broken": `),
		jsonMsg("msg-good-1", "evt_good_1", validJSONPayload),
		jsonMsg("msg-good-2", "evt_good_2", validJSONPayload),
	}

	mockBuf := &mockWorkerBuffer{messages: messages}
	normalizedStore := normalized.NewMemoryStore()
	quarantineStore := quarantine.NewMemoryStore()

	w, err := setupTestWorkerWithStores(
		mockBuf, raw.NewMemoryRawStore(), buffer.NewMemoryIdempotencyStore(),
		normalizedStore, quarantineStore, Config{BatchSize: 10, Concurrency: 3},
	)
	if err != nil {
		t.Fatalf("setup: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()
	_ = w.Start(ctx)

	waitFor(t, time.Second, func() bool {
		count, _ := normalizedStore.Count(context.Background())
		return count == 2
	}, "both healthy events to be persisted")

	// The poison pill is quarantined, not left pending.
	entry, err := quarantineStore.Get(context.Background(), "evt_poison")
	if err != nil {
		t.Fatalf("expected the poison pill to be quarantined: %v", err)
	}
	if entry.Type != failure.TypeParseFailed {
		t.Errorf("expected failure type %q, got %q", failure.TypeParseFailed, entry.Type)
	}

	// Every message is ACKed: none may linger in the pending list.
	acked := map[string]bool{}
	for _, id := range mockBuf.acked {
		acked[id] = true
	}
	for _, id := range []string{"msg-poison", "msg-good-1", "msg-good-2"} {
		if !acked[id] {
			t.Errorf("expected %s to be ACKed, acked=%v", id, mockBuf.acked)
		}
	}

	// Both healthy events are stored, exactly once each.
	if count, _ := normalizedStore.Count(context.Background()); count != 2 {
		t.Errorf("expected 2 normalized records, got %d", count)
	}
	for _, eventID := range []string{"evt_good_1", "evt_good_2"} {
		if _, err := normalizedStore.Get(context.Background(), eventID); err != nil {
			t.Errorf("expected %s to be persisted: %v", eventID, err)
		}
	}
}
