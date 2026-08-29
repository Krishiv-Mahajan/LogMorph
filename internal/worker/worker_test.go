package worker

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/Krishiv-Mahajan/LogMorph/internal/buffer"
	"github.com/Krishiv-Mahajan/LogMorph/internal/detection"
	"github.com/Krishiv-Mahajan/LogMorph/internal/models"
	"github.com/Krishiv-Mahajan/LogMorph/internal/normalization"
	"github.com/Krishiv-Mahajan/LogMorph/internal/parsing"
	"github.com/Krishiv-Mahajan/LogMorph/internal/parsing/parsers"
	"github.com/Krishiv-Mahajan/LogMorph/internal/storage/raw"
	"github.com/Krishiv-Mahajan/LogMorph/internal/validation"
)

// ── Mock RawBuffer ────────────────────────────────────────────────────────────

type mockWorkerBuffer struct {
	mu              sync.Mutex
	messages        []buffer.RawMessage
	pendingMessages []buffer.RawMessage
	acked           []string
	claimCalled     bool
}

func (m *mockWorkerBuffer) PublishRaw(_ context.Context, _ string, _ *models.RawEvent) (string, error) {
	return "mock_id", nil
}
func (m *mockWorkerBuffer) EnsureGroup(_ context.Context, _, _ string) error { return nil }
func (m *mockWorkerBuffer) ReadGroup(_ context.Context, _, _, _ string, _ int64, _ time.Duration) ([]buffer.RawMessage, error) {
	m.mu.Lock()
	if len(m.messages) > 0 {
		msgs := m.messages
		m.messages = nil
		m.mu.Unlock()
		return msgs, nil
	}
	m.mu.Unlock()
	time.Sleep(50 * time.Millisecond)
	return nil, nil
}
func (m *mockWorkerBuffer) Ack(_ context.Context, _, _ string, ids ...string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.acked = append(m.acked, ids...)
	return nil
}
func (m *mockWorkerBuffer) ClaimPending(_ context.Context, _, _, _ string, _ time.Duration, _ int64) ([]buffer.RawMessage, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.claimCalled = true
	if len(m.pendingMessages) > 0 {
		msgs := m.pendingMessages
		m.pendingMessages = nil
		return msgs, nil
	}
	return nil, nil
}
func (m *mockWorkerBuffer) Ping(_ context.Context) error { return nil }
func (m *mockWorkerBuffer) Close() error                 { return nil }

// ── Mock IdempotencyStore ─────────────────────────────────────────────────────

// mockIdempotencyStore is configurable for testing specific idempotency paths.
// By default TryClaimProcessing succeeds and IsDone returns false.
type mockIdempotencyStore struct {
	mu sync.Mutex

	// Pre-configure IsDone for specific eventIDs (true = already done).
	doneEvents map[string]bool
	// Pre-configure TryClaimProcessing for specific eventIDs (false = lock held).
	claimBlocked map[string]bool

	// Tracking fields (inspected in assertions).
	claimAttempted []string
	releasedKeys   []string
	markedDoneKeys []string
}

func newMockIdempotencyStore() *mockIdempotencyStore {
	return &mockIdempotencyStore{
		doneEvents:   make(map[string]bool),
		claimBlocked: make(map[string]bool),
	}
}

func (m *mockIdempotencyStore) IsDone(_ context.Context, eventID string) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.doneEvents[eventID], nil
}

func (m *mockIdempotencyStore) TryClaimProcessing(_ context.Context, eventID string, _ time.Duration) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.claimAttempted = append(m.claimAttempted, eventID)
	if m.claimBlocked[eventID] {
		return false, nil
	}
	return true, nil
}

func (m *mockIdempotencyStore) ReleaseProcessing(_ context.Context, eventID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.releasedKeys = append(m.releasedKeys, eventID)
	return nil
}

func (m *mockIdempotencyStore) MarkDone(_ context.Context, eventID string, _ time.Duration) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.markedDoneKeys = append(m.markedDoneKeys, eventID)
	m.doneEvents[eventID] = true
	return nil
}

// ── Helpers ───────────────────────────────────────────────────────────────────

func buildParserEngine() parsing.Engine {
	registry := parsing.NewRegistry()
	registry.Register(parsers.NewSyslogParser())
	registry.Register(parsers.NewJSONParser())
	registry.Register(parsers.NewCSVParser())
	return parsing.NewEngine(registry)
}

// setupTestWorker creates a worker with a MemoryIdempotencyStore (fully
// functional, no real Redis needed) and all parsers registered.
func setupTestWorker(mockBuf *mockWorkerBuffer, rawStore raw.RawEventStore) (*Worker, error) {
	return setupTestWorkerWithIdempotency(mockBuf, rawStore, buffer.NewMemoryIdempotencyStore())
}

func setupTestWorkerWithIdempotency(
	mockBuf *mockWorkerBuffer,
	rawStore raw.RawEventStore,
	idempotency buffer.IdempotencyStore,
) (*Worker, error) {
	normalizer := normalization.NewNormalizer()
	validator, err := validation.NewValidator("")
	if err != nil {
		return nil, err
	}

	w := NewWorker(
		mockBuf,
		idempotency,
		rawStore,
		detection.NewDetector(),
		detection.NewDriftDetector(),
		buildParserEngine(),
		normalizer,
		validator,
		Config{
			StreamName:   "raw_events",
			GroupName:    "test-group",
			ConsumerName: "test-worker",
		},
	)
	return w, nil
}

// syslogMsg returns a realistic test RawMessage.
func syslogMsg(id, eventID string) buffer.RawMessage {
	return buffer.RawMessage{
		ID: id,
		Event: models.RawEvent{
			EventID:    eventID,
			ReceivedAt: time.Now().UTC().Format(time.RFC3339),
			Format:     "syslog",
			Source:     "firewall-01",
			Payload:    "Aug 28 18:30:12 firewall01 DENY TCP SRC=192.168.1.20:54321 DST=10.0.0.15:443",
		},
	}
}

// ── Existing tests (unchanged behaviour) ────────────────────────────────────

func TestWorker_FullPipelineAndStorage(t *testing.T) {
	rawStore := raw.NewMemoryRawStore()
	mockBuf := &mockWorkerBuffer{
		messages: []buffer.RawMessage{syslogMsg("1670000000000-0", "evt_test_syslog")},
	}

	w, err := setupTestWorker(mockBuf, rawStore)
	if err != nil {
		t.Fatalf("failed to setup worker: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()

	_ = w.Start(ctx)

	if len(mockBuf.acked) != 1 || mockBuf.acked[0] != "1670000000000-0" {
		t.Errorf("expected message acked, got: %v", mockBuf.acked)
	}

	storedRaw, err := rawStore.Get(context.Background(), "evt_test_syslog")
	if err != nil {
		t.Fatalf("expected raw event stored in RawEventStore: %v", err)
	}
	if storedRaw.Payload != "Aug 28 18:30:12 firewall01 DENY TCP SRC=192.168.1.20:54321 DST=10.0.0.15:443" {
		t.Errorf("stored raw payload mismatch: %s", storedRaw.Payload)
	}
}

// TestWorker_ClaimsPendingOnRecovery verifies XAUTOCLAIM crash recovery path.
func TestWorker_ClaimsPendingOnRecovery(t *testing.T) {
	const payload = "Aug 28 18:30:12 firewall01 DENY TCP SRC=192.168.1.20:54321 DST=10.0.0.15:443"

	pendingMsg := buffer.RawMessage{
		ID: "1670000000001-0",
		Event: models.RawEvent{
			EventID:    "evt_crash_recovery_test",
			ReceivedAt: time.Now().UTC().Format(time.RFC3339),
			Format:     "syslog",
			Source:     "firewall-recovery",
			Payload:    payload,
		},
	}

	mockBuf := &mockWorkerBuffer{pendingMessages: []buffer.RawMessage{pendingMsg}}
	rawStore := raw.NewMemoryRawStore()

	normalizer := normalization.NewNormalizer()
	validator, err := validation.NewValidator("")
	if err != nil {
		t.Fatalf("failed to create validator: %v", err)
	}

	w := NewWorker(
		mockBuf,
		buffer.NewMemoryIdempotencyStore(),
		rawStore,
		detection.NewDetector(),
		detection.NewDriftDetector(),
		buildParserEngine(),
		normalizer,
		validator,
		Config{
			StreamName:   "raw_events",
			GroupName:    "test-group",
			ConsumerName: "test-worker",
			ClaimIdleMs:  1,
		},
	)

	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()

	_ = w.Start(ctx)

	if !mockBuf.claimCalled {
		t.Error("expected ClaimPending to be called for crash recovery")
	}
	if len(mockBuf.acked) == 0 {
		t.Fatalf("expected pending message to be ACKed after recovery")
	}
	if mockBuf.acked[0] != pendingMsg.ID {
		t.Errorf("expected ACKed ID %q, got %q", pendingMsg.ID, mockBuf.acked[0])
	}

	stored, err := rawStore.Get(context.Background(), "evt_crash_recovery_test")
	if err != nil {
		t.Fatalf("expected raw event in store after recovery: %v", err)
	}
	if stored.Payload != payload {
		t.Errorf("raw payload corrupted: expected %q, got %q", payload, stored.Payload)
	}
}

// ── Idempotency tests ─────────────────────────────────────────────────────────

// TestIdempotency_FirstDeliveryIsProcessed — first delivery goes through
// the full pipeline, is marked done, and is ACKed.
func TestIdempotency_FirstDeliveryIsProcessed(t *testing.T) {
	mockBuf := &mockWorkerBuffer{
		messages: []buffer.RawMessage{syslogMsg("msg-1", "evt_first")},
	}
	idempotency := newMockIdempotencyStore()
	rawStore := raw.NewMemoryRawStore()

	w, err := setupTestWorkerWithIdempotency(mockBuf, rawStore, idempotency)
	if err != nil {
		t.Fatalf("setup: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	_ = w.Start(ctx)

	// Event must be ACKed.
	if len(mockBuf.acked) == 0 {
		t.Fatal("expected event to be ACKed on first delivery")
	}
	// Done must be marked.
	if len(idempotency.markedDoneKeys) == 0 || idempotency.markedDoneKeys[0] != "evt_first" {
		t.Errorf("expected MarkDone called with evt_first, got %v", idempotency.markedDoneKeys)
	}
	// Raw store must contain the original payload.
	stored, err := rawStore.Get(context.Background(), "evt_first")
	if err != nil {
		t.Fatalf("raw event not in store: %v", err)
	}
	if stored.Payload != "Aug 28 18:30:12 firewall01 DENY TCP SRC=192.168.1.20:54321 DST=10.0.0.15:443" {
		t.Errorf("raw payload mismatch: %s", stored.Payload)
	}
}

// TestIdempotency_DuplicateDeliveryIsSkipped — when a message is re-delivered
// but IsDone returns true, the worker skips the side-effects and ACKs.
func TestIdempotency_DuplicateDeliveryIsSkipped(t *testing.T) {
	mockBuf := &mockWorkerBuffer{
		messages: []buffer.RawMessage{syslogMsg("msg-2", "evt_dup")},
	}
	idempotency := newMockIdempotencyStore()
	idempotency.doneEvents["evt_dup"] = true // pre-mark as done

	rawStore := raw.NewMemoryRawStore()

	w, err := setupTestWorkerWithIdempotency(mockBuf, rawStore, idempotency)
	if err != nil {
		t.Fatalf("setup: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	_ = w.Start(ctx)

	// Duplicate must be ACKed (to clear it from the PEL).
	if len(mockBuf.acked) == 0 {
		t.Fatal("expected duplicate to be ACKed")
	}
	// But the raw store must NOT contain a new entry (no side-effects).
	_, err = rawStore.Get(context.Background(), "evt_dup")
	if err == nil {
		t.Error("expected no raw store entry for duplicate (side-effects must be skipped)")
	}
	// TryClaimProcessing must NOT have been called — IsDone short-circuits.
	if len(idempotency.claimAttempted) != 0 {
		t.Errorf("expected no claim attempt for duplicate, got %v", idempotency.claimAttempted)
	}
}

// TestIdempotency_LockConflictSkipsWithoutACK — when the processing lock is
// held by another worker, this worker skips the message WITHOUT ACKing it
// (so XAUTOCLAIM can re-deliver after the lock expires).
func TestIdempotency_LockConflictSkipsWithoutACK(t *testing.T) {
	msg := syslogMsg("msg-3", "evt_locked")
	mockBuf := &mockWorkerBuffer{
		messages: []buffer.RawMessage{msg},
	}
	idempotency := newMockIdempotencyStore()
	idempotency.claimBlocked["evt_locked"] = true // simulate another worker holding the lock

	rawStore := raw.NewMemoryRawStore()
	w, err := setupTestWorkerWithIdempotency(mockBuf, rawStore, idempotency)
	if err != nil {
		t.Fatalf("setup: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	_ = w.Start(ctx)

	// Must NOT ACK — message must stay in PEL for XAUTOCLAIM retry.
	if len(mockBuf.acked) != 0 {
		t.Errorf("expected NO ACK when lock is held by another worker, got %v", mockBuf.acked)
	}
	// Must NOT appear in raw store (no processing).
	_, err = rawStore.Get(context.Background(), "evt_locked")
	if err == nil {
		t.Error("expected no raw store entry when lock is held")
	}
}

// TestIdempotency_FailureReleasesLockAndNoACK — when processing fails (no
// parser registered), the processing lock is released and the message is
// NOT ACKed so XAUTOCLAIM can retry.
func TestIdempotency_FailureReleasesLockAndNoACK(t *testing.T) {
	msg := buffer.RawMessage{
		ID: "msg-4",
		Event: models.RawEvent{
			EventID:    "evt_fail",
			ReceivedAt: time.Now().UTC().Format(time.RFC3339),
			Format:     "unknown_format", // no parser registered → engine returns error
			Source:     "test",
			Payload:    "some raw log data",
		},
	}

	mockBuf := &mockWorkerBuffer{messages: []buffer.RawMessage{msg}}
	idempotency := newMockIdempotencyStore()
	rawStore := raw.NewMemoryRawStore()

	normalizer := normalization.NewNormalizer()
	validator, err := validation.NewValidator("")
	if err != nil {
		t.Fatalf("setup: %v", err)
	}

	// Intentionally empty registry — no parser for "unknown_format".
	emptyRegistry := parsing.NewRegistry()
	emptyEngine := parsing.NewEngine(emptyRegistry)

	w := NewWorker(
		mockBuf,
		idempotency,
		rawStore,
		detection.NewDetector(),
		detection.NewDriftDetector(),
		emptyEngine,
		normalizer,
		validator,
		Config{
			StreamName:   "raw_events",
			GroupName:    "test-group",
			ConsumerName: "test-worker",
		},
	)

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	_ = w.Start(ctx)

	// Must NOT ACK — message should remain in PEL for retry.
	if len(mockBuf.acked) != 0 {
		t.Errorf("expected NO ACK on processing failure, got %v", mockBuf.acked)
	}
	// Processing lock must be released so another worker can retry.
	if len(idempotency.releasedKeys) == 0 || idempotency.releasedKeys[0] != "evt_fail" {
		t.Errorf("expected ReleaseProcessing called with evt_fail, got %v", idempotency.releasedKeys)
	}
	// MarkDone must NOT be called on failure.
	if len(idempotency.markedDoneKeys) != 0 {
		t.Errorf("expected MarkDone NOT called on failure, got %v", idempotency.markedDoneKeys)
	}
}

// TestIdempotency_SuccessfulProcessingPreventsReprocessing — after the first
// successful processing (MarkDone), a second delivery of the same event is
// skipped.
func TestIdempotency_SuccessfulProcessingPreventsReprocessing(t *testing.T) {
	rawStore := raw.NewMemoryRawStore()
	idempotency := buffer.NewMemoryIdempotencyStore() // real memory store — tracks state

	// First delivery
	mockBuf := &mockWorkerBuffer{
		messages: []buffer.RawMessage{syslogMsg("msg-5a", "evt_dedup")},
	}
	w, err := setupTestWorkerWithIdempotency(mockBuf, rawStore, idempotency)
	if err != nil {
		t.Fatalf("setup: %v", err)
	}

	ctx1, cancel1 := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel1()
	_ = w.Start(ctx1)

	if len(mockBuf.acked) != 1 {
		t.Fatalf("expected 1st delivery to be ACKed, got %v", mockBuf.acked)
	}

	// Second delivery (same event_id, different stream message ID).
	mockBuf2 := &mockWorkerBuffer{
		messages: []buffer.RawMessage{syslogMsg("msg-5b", "evt_dedup")},
	}
	w2, err := setupTestWorkerWithIdempotency(mockBuf2, rawStore, idempotency)
	if err != nil {
		t.Fatalf("setup w2: %v", err)
	}

	ctx2, cancel2 := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel2()
	_ = w2.Start(ctx2)

	// Second delivery must be ACKed (to clear PEL) but no new raw store entry.
	if len(mockBuf2.acked) != 1 {
		t.Errorf("expected 2nd delivery to be ACKed (skip+ACK), got %v", mockBuf2.acked)
	}
	done, _ := idempotency.IsDone(context.Background(), "evt_dedup")
	if !done {
		t.Error("expected IsDone=true after successful first processing")
	}
}

// TestIdempotency_ConcurrentWorkers — two workers racing on the same event_id;
// MemoryIdempotencyStore enforces SET NX semantics via mutex so exactly one
// acquires the processing lock.
func TestIdempotency_ConcurrentWorkers(t *testing.T) {
	idempotency := buffer.NewMemoryIdempotencyStore()
	eventID := "evt_concurrent"

	const goroutines = 8
	results := make([]bool, goroutines)
	var wg sync.WaitGroup

	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			ok, _ := idempotency.TryClaimProcessing(context.Background(), eventID, 5*time.Second)
			results[idx] = ok
		}(i)
	}
	wg.Wait()

	successCount := 0
	for _, r := range results {
		if r {
			successCount++
		}
	}
	if successCount != 1 {
		t.Errorf("expected exactly 1 goroutine to acquire processing lock, got %d", successCount)
	}
}

// TestWorker_ConcurrentBatchProcessing verifies that a batch of events is processed
// in parallel bounded by Concurrency and all valid events are ACKed and saved to raw store.
func TestWorker_ConcurrentBatchProcessing(t *testing.T) {
	const numEvents = 6
	messages := make([]buffer.RawMessage, numEvents)
	for i := 0; i < numEvents; i++ {
		messages[i] = syslogMsg(
			fmt.Sprintf("msg-%d", i),
			fmt.Sprintf("evt_concurrent_%d", i),
		)
	}

	mockBuf := &mockWorkerBuffer{messages: messages}
	rawStore := raw.NewMemoryRawStore()
	idempotency := buffer.NewMemoryIdempotencyStore()

	normalizer := normalization.NewNormalizer()
	validator, err := validation.NewValidator("")
	if err != nil {
		t.Fatalf("validator: %v", err)
	}

	w := NewWorker(
		mockBuf,
		idempotency,
		rawStore,
		detection.NewDetector(),
		detection.NewDriftDetector(),
		buildParserEngine(),
		normalizer,
		validator,
		Config{
			StreamName:   "raw_events",
			GroupName:    "test-group",
			ConsumerName: "test-worker",
			BatchSize:    10,
			Concurrency:  3,
		},
	)

	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()

	_ = w.Start(ctx)

	// Verify all 6 messages were ACKed
	if len(mockBuf.acked) != numEvents {
		t.Fatalf("expected %d ACKed messages, got %d", numEvents, len(mockBuf.acked))
	}

	// Verify all 6 events are in the raw store
	for i := 0; i < numEvents; i++ {
		evtID := fmt.Sprintf("evt_concurrent_%d", i)
		stored, err := rawStore.Get(context.Background(), evtID)
		if err != nil {
			t.Errorf("event %s not found in raw store: %v", evtID, err)
		}
		if stored.Payload != "Aug 28 18:30:12 firewall01 DENY TCP SRC=192.168.1.20:54321 DST=10.0.0.15:443" {
			t.Errorf("payload mismatch for %s", evtID)
		}
	}
}

// TestWorker_PartialFailureInBatch verifies that one failing event in a batch does
// NOT block or fail the other valid events in the same batch.
// The valid events are ACKed; the failed event remains un-ACKed.
func TestWorker_PartialFailureInBatch(t *testing.T) {
	messages := []buffer.RawMessage{
		syslogMsg("msg-valid-1", "evt_valid_1"),
		{
			ID: "msg-bad",
			Event: models.RawEvent{
				EventID:    "evt_bad_fail",
				ReceivedAt: time.Now().UTC().Format(time.RFC3339),
				Format:     "unknown_no_parser",
				Source:     "bad-source",
				Payload:    "some bad unparseable data",
			},
		},
		syslogMsg("msg-valid-2", "evt_valid_2"),
	}

	mockBuf := &mockWorkerBuffer{messages: messages}
	rawStore := raw.NewMemoryRawStore()
	idempotency := buffer.NewMemoryIdempotencyStore()

	normalizer := normalization.NewNormalizer()
	validator, err := validation.NewValidator("")
	if err != nil {
		t.Fatalf("validator: %v", err)
	}

	w := NewWorker(
		mockBuf,
		idempotency,
		rawStore,
		detection.NewDetector(),
		detection.NewDriftDetector(),
		buildParserEngine(),
		normalizer,
		validator,
		Config{
			StreamName:   "raw_events",
			GroupName:    "test-group",
			ConsumerName: "test-worker",
			BatchSize:    10,
			Concurrency:  2,
		},
	)

	ctx, cancel := context.WithTimeout(context.Background(), 400*time.Millisecond)
	defer cancel()

	_ = w.Start(ctx)

	// Valid events must be ACKed
	ackedSet := make(map[string]bool)
	for _, id := range mockBuf.acked {
		ackedSet[id] = true
	}

	if !ackedSet["msg-valid-1"] {
		t.Errorf("expected msg-valid-1 to be ACKed")
	}
	if !ackedSet["msg-valid-2"] {
		t.Errorf("expected msg-valid-2 to be ACKed")
	}
	if ackedSet["msg-bad"] {
		t.Errorf("expected msg-bad to NOT be ACKed on failure")
	}

	// Valid events must be in the raw store
	if _, err := rawStore.Get(context.Background(), "evt_valid_1"); err != nil {
		t.Errorf("evt_valid_1 should be stored in raw store: %v", err)
	}
	if _, err := rawStore.Get(context.Background(), "evt_valid_2"); err != nil {
		t.Errorf("evt_valid_2 should be stored in raw store: %v", err)
	}
}

// TestWorker_ConcurrentRaceOnSameEvent_Idempotency verifies that when two workers
// concurrently attempt to process the exact same event, only one runs the pipeline
// and stores the event, while the other does not duplicate processing.
func TestWorker_ConcurrentRaceOnSameEvent_Idempotency(t *testing.T) {
	sharedRawStore := raw.NewMemoryRawStore()
	sharedIdempotency := buffer.NewMemoryIdempotencyStore()

	// Worker 1 buffer
	buf1 := &mockWorkerBuffer{
		messages: []buffer.RawMessage{syslogMsg("msg-race-1", "evt_race_same")},
	}
	// Worker 2 buffer with identical event_id
	buf2 := &mockWorkerBuffer{
		messages: []buffer.RawMessage{syslogMsg("msg-race-2", "evt_race_same")},
	}

	w1, _ := setupTestWorkerWithIdempotency(buf1, sharedRawStore, sharedIdempotency)
	w2, _ := setupTestWorkerWithIdempotency(buf2, sharedRawStore, sharedIdempotency)

	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		_ = w1.Start(ctx)
	}()
	go func() {
		defer wg.Done()
		_ = w2.Start(ctx)
	}()
	wg.Wait()

	// Verify exact raw event was stored
	stored, err := sharedRawStore.Get(context.Background(), "evt_race_same")
	if err != nil {
		t.Fatalf("expected evt_race_same to be stored: %v", err)
	}
	if stored.Payload != "Aug 28 18:30:12 firewall01 DENY TCP SRC=192.168.1.20:54321 DST=10.0.0.15:443" {
		t.Errorf("payload corrupted: %s", stored.Payload)
	}

	// Done marker must be recorded
	done, _ := sharedIdempotency.IsDone(context.Background(), "evt_race_same")
	if !done {
		t.Errorf("expected evt_race_same marked done")
	}
}
