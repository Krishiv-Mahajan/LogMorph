package worker

import (
	"context"
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

type mockWorkerBuffer struct {
	messages        []buffer.RawMessage
	pendingMessages []buffer.RawMessage
	acked           []string
	claimCalled     bool
}

func (m *mockWorkerBuffer) PublishRaw(ctx context.Context, stream string, event *models.RawEvent) (string, error) {
	return "mock_id", nil
}

func (m *mockWorkerBuffer) EnsureGroup(ctx context.Context, stream string, group string) error {
	return nil
}

func (m *mockWorkerBuffer) ReadGroup(ctx context.Context, stream, group, consumer string, count int64, block time.Duration) ([]buffer.RawMessage, error) {
	if len(m.messages) > 0 {
		msgs := m.messages
		m.messages = nil
		return msgs, nil
	}
	time.Sleep(50 * time.Millisecond)
	return nil, nil
}

func (m *mockWorkerBuffer) Ack(ctx context.Context, stream, group string, ids ...string) error {
	m.acked = append(m.acked, ids...)
	return nil
}

func (m *mockWorkerBuffer) ClaimPending(ctx context.Context, stream, group, consumer string, minIdleTime time.Duration, count int64) ([]buffer.RawMessage, error) {
	m.claimCalled = true
	if len(m.pendingMessages) > 0 {
		msgs := m.pendingMessages
		m.pendingMessages = nil
		return msgs, nil
	}
	return nil, nil
}

func (m *mockWorkerBuffer) Ping(ctx context.Context) error {
	return nil
}

func (m *mockWorkerBuffer) Close() error {
	return nil
}

func setupTestWorker(mockBuf *mockWorkerBuffer, rawStore raw.RawEventStore) (*Worker, error) {
	detector := detection.NewDetector()
	driftDetector := detection.NewDriftDetector()
	registry := parsing.NewRegistry()
	registry.Register(parsers.NewSyslogParser())
	registry.Register(parsers.NewJSONParser())
	registry.Register(parsers.NewCSVParser())
	parserEngine := parsing.NewEngine(registry)
	normalizer := normalization.NewNormalizer()
	validator, err := validation.NewValidator("")
	if err != nil {
		return nil, err
	}

	w := NewWorker(
		mockBuf,
		rawStore,
		detector,
		driftDetector,
		parserEngine,
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

func TestWorker_FullPipelineAndStorage(t *testing.T) {
	rawStore := raw.NewMemoryRawStore()
	mockBuf := &mockWorkerBuffer{
		messages: []buffer.RawMessage{
			{
				ID: "1670000000000-0",
				Event: models.RawEvent{
					EventID:    "evt_test_syslog",
					ReceivedAt: time.Now().UTC().Format(time.RFC3339),
					Format:     "syslog",
					Source:     "firewall-01",
					Payload:    "Aug 28 18:30:12 firewall01 DENY TCP SRC=192.168.1.20:54321 DST=10.0.0.15:443",
				},
			},
		},
	}

	w, err := setupTestWorker(mockBuf, rawStore)
	if err != nil {
		t.Fatalf("failed to setup worker: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()

	_ = w.Start(ctx)

	// 1. Verify Redis Message was acknowledged
	if len(mockBuf.acked) != 1 || mockBuf.acked[0] != "1670000000000-0" {
		t.Errorf("expected message acked, got: %v", mockBuf.acked)
	}

	// 2. Verify Raw Event was stored immutably in RawEventStore
	storedRaw, err := rawStore.Get(context.Background(), "evt_test_syslog")
	if err != nil {
		t.Fatalf("expected raw event stored in RawEventStore: %v", err)
	}
	if storedRaw.Payload != "Aug 28 18:30:12 firewall01 DENY TCP SRC=192.168.1.20:54321 DST=10.0.0.15:443" {
		t.Errorf("stored raw payload mismatch: %s", storedRaw.Payload)
	}
}

// TestWorker_ClaimsPendingOnRecovery verifies that when ClaimIdleMs > 0 the worker
// calls ClaimPending, processes the returned messages through the full pipeline,
// ACKs them, and stores the exact original payload in the raw event store.
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

	// Buffer starts empty (no new messages); the pending message simulates a
	// message left behind by a crashed worker.
	mockBuf := &mockWorkerBuffer{
		pendingMessages: []buffer.RawMessage{pendingMsg},
	}
	rawStore := raw.NewMemoryRawStore()

	detector := detection.NewDetector()
	driftDetector := detection.NewDriftDetector()
	registry := parsing.NewRegistry()
	registry.Register(parsers.NewSyslogParser())
	registry.Register(parsers.NewJSONParser())
	registry.Register(parsers.NewCSVParser())
	parserEngine := parsing.NewEngine(registry)
	normalizer := normalization.NewNormalizer()
	validator, err := validation.NewValidator("")
	if err != nil {
		t.Fatalf("failed to create validator: %v", err)
	}

	w := NewWorker(
		mockBuf,
		rawStore,
		detector,
		driftDetector,
		parserEngine,
		normalizer,
		validator,
		Config{
			StreamName:   "raw_events",
			GroupName:    "test-group",
			ConsumerName: "test-worker",
			// 1 ms idle threshold so the claim fires immediately in the test.
			ClaimIdleMs: 1,
		},
	)

	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()

	_ = w.Start(ctx)

	// 1. Verify ClaimPending was called.
	if !mockBuf.claimCalled {
		t.Error("expected ClaimPending to be called for crash recovery, but it was not")
	}

	// 2. Verify the reclaimed message was acknowledged.
	if len(mockBuf.acked) == 0 {
		t.Fatalf("expected pending message to be ACKed after recovery, acked list is empty")
	}
	if mockBuf.acked[0] != pendingMsg.ID {
		t.Errorf("expected ACKed ID %q, got %q", pendingMsg.ID, mockBuf.acked[0])
	}

	// 3. Verify exact raw payload was preserved in the immutable raw store.
	stored, err := rawStore.Get(context.Background(), "evt_crash_recovery_test")
	if err != nil {
		t.Fatalf("expected raw event in store after recovery: %v", err)
	}
	if stored.Payload != payload {
		t.Errorf("raw payload corrupted: expected %q, got %q", payload, stored.Payload)
	}
}
