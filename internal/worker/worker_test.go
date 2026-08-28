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
	messages []buffer.RawMessage
	acked    []string
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
