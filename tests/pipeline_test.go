package tests

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/Krishiv-Mahajan/LogMorph/internal/buffer"
	"github.com/Krishiv-Mahajan/LogMorph/internal/detection"
	"github.com/Krishiv-Mahajan/LogMorph/internal/failure"
	"github.com/Krishiv-Mahajan/LogMorph/internal/ingestion"
	"github.com/Krishiv-Mahajan/LogMorph/internal/models"
	"github.com/Krishiv-Mahajan/LogMorph/internal/normalization"
	"github.com/Krishiv-Mahajan/LogMorph/internal/parsing"
	"github.com/Krishiv-Mahajan/LogMorph/internal/parsing/parsers"
	"github.com/Krishiv-Mahajan/LogMorph/internal/storage/normalized"
	"github.com/Krishiv-Mahajan/LogMorph/internal/storage/quarantine"
	"github.com/Krishiv-Mahajan/LogMorph/internal/storage/raw"
	"github.com/Krishiv-Mahajan/LogMorph/internal/validation"
	"github.com/Krishiv-Mahajan/LogMorph/internal/worker"
)

// inMemoryBuffer stands in for Redis Streams. The worker consumes messages on
// its own goroutines, so every field is guarded by mu.
type inMemoryBuffer struct {
	mu        sync.Mutex
	messages  []buffer.RawMessage
	acked     []string
	published int
}

func (b *inMemoryBuffer) PublishRaw(ctx context.Context, stream string, event *models.RawEvent) (string, error) {
	b.mu.Lock()
	defer b.mu.Unlock()

	b.published++
	id := fmt.Sprintf("msg_%d", b.published)
	b.messages = append(b.messages, buffer.RawMessage{
		ID:    id,
		Event: *event,
	})
	return id, nil
}

func (b *inMemoryBuffer) EnsureGroup(ctx context.Context, stream string, group string) error {
	return nil
}

func (b *inMemoryBuffer) ReadGroup(ctx context.Context, stream, group, consumer string, count int64, block time.Duration) ([]buffer.RawMessage, error) {
	b.mu.Lock()
	if len(b.messages) > 0 {
		msgs := b.messages
		b.messages = nil
		b.mu.Unlock()
		return msgs, nil
	}
	b.mu.Unlock()

	// Avoid a hot spin when the worker loop is waiting for work.
	time.Sleep(10 * time.Millisecond)
	return nil, nil
}

func (b *inMemoryBuffer) Ack(ctx context.Context, stream, group string, ids ...string) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.acked = append(b.acked, ids...)
	return nil
}

func (b *inMemoryBuffer) ClaimPending(ctx context.Context, stream, group, consumer string, minIdleTime time.Duration, count int64) ([]buffer.RawMessage, error) {
	return nil, nil
}

func (b *inMemoryBuffer) Ping(ctx context.Context) error {
	return nil
}

func (b *inMemoryBuffer) Close() error {
	return nil
}

// takeMessages drains and returns the buffered messages, simulating the worker
// consuming from the stream.
func (b *inMemoryBuffer) takeMessages() []buffer.RawMessage {
	b.mu.Lock()
	defer b.mu.Unlock()

	msgs := b.messages
	b.messages = nil
	return msgs
}

// ackedIDs returns a snapshot of the acknowledged stream message ids.
func (b *inMemoryBuffer) ackedIDs() []string {
	b.mu.Lock()
	defer b.mu.Unlock()

	return append([]string(nil), b.acked...)
}

func TestFullTargetArchitecture_E2E(t *testing.T) {
	rawBuf := &inMemoryBuffer{}
	rawStore := raw.NewMemoryRawStore()
	normalizedStore := normalized.NewMemoryStore()
	quarantineStore := quarantine.NewMemoryStore()

	// Ingestion Setup
	ingestService := ingestion.NewService(rawBuf, "raw_events")
	ingestHandler := ingestion.NewHandler(ingestService)

	// Worker Setup
	detector := detection.NewDetector()
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

	w := worker.NewWorker(
		rawBuf,
		buffer.NewMemoryIdempotencyStore(),
		rawStore,
		detector,
		parserEngine,
		normalizer,
		validator,
		worker.Config{
			StreamName:      "raw_events",
			GroupName:       "test-group",
			ConsumerName:    "test-worker",
			NormalizedStore: normalizedStore,
			QuarantineStore: quarantineStore,
		},
	)

	samples := []struct {
		name       string
		samplePath string
		hint       string
	}{
		{
			name:       "Syslog Sample",
			samplePath: "../samples/syslog/sample.log",
			hint:       "syslog",
		},
		{
			name:       "JSON Sample",
			samplePath: "../samples/json/sample.json",
			hint:       "json",
		},
		{
			name:       "CSV Sample",
			samplePath: "../samples/csv/sample.csv",
			hint:       "csv",
		},
	}

	var results []*worker.PipelineResult

	for _, s := range samples {
		t.Run(s.name, func(t *testing.T) {
			content, err := os.ReadFile(s.samplePath)
			if err != nil {
				t.Fatalf("failed to read sample: %v", err)
			}

			// 1. POST to /ingest
			reqBody := ingestion.IngestRequest{
				Format:  s.hint,
				Source:  "firewall-01",
				Payload: string(content),
			}
			reqBytes, _ := json.Marshal(reqBody)
			req := httptest.NewRequest(http.MethodPost, "/ingest", bytes.NewBuffer(reqBytes))
			rec := httptest.NewRecorder()

			ingestHandler.HandleIngest(rec, req)

			if rec.Code != http.StatusAccepted {
				t.Fatalf("expected 202 Accepted, got %d: %s", rec.Code, rec.Body.String())
			}

			var ingestResp ingestion.IngestResponse
			if err := json.Unmarshal(rec.Body.Bytes(), &ingestResp); err != nil {
				t.Fatalf("failed to decode ingest response: %v", err)
			}

			// 2. Verify buffered in Redis
			buffered := rawBuf.takeMessages()
			if len(buffered) == 0 {
				t.Fatalf("expected message buffered in Redis, found none")
			}
			rawMsg := buffered[0] // simulate consuming

			// 3. Process via Worker
			res, err := w.ProcessSingleEvent(context.Background(), rawMsg.Event)
			if err != nil {
				t.Fatalf("worker process failed: %v", err)
			}
			if !res.Valid {
				t.Fatalf("event failed validation: %+v", res.Errors)
			}

			// 4. Verify Immutable Raw Copy in RawEventStore
			storedRaw, err := rawStore.Get(context.Background(), ingestResp.EventID)
			if err != nil {
				t.Fatalf("raw event not found in RawEventStore: %v", err)
			}
			if storedRaw.Payload != string(content) {
				t.Errorf("stored raw payload mismatch: expected %q, got %q", string(content), storedRaw.Payload)
			}

			// 5. Verify the normalized event reached the PostgreSQL store with a
			// reference to the immutable raw object.
			storedRec, err := normalizedStore.Get(context.Background(), ingestResp.EventID)
			if err != nil {
				t.Fatalf("normalized event not found in the normalized store: %v", err)
			}
			if storedRec.Event.EventID != ingestResp.EventID {
				t.Errorf("normalized event id mismatch: %q", storedRec.Event.EventID)
			}
			if storedRec.RawObjectKey != raw.ObjectKey(ingestResp.EventID) {
				t.Errorf("expected raw object key %q, got %q", raw.ObjectKey(ingestResp.EventID), storedRec.RawObjectKey)
			}

			results = append(results, res)
		})
	}

	// 5. Verify Universal Event Schema Convergence
	if len(results) != 3 {
		t.Fatalf("expected 3 results, got %d", len(results))
	}

	for _, r := range results {
		evt := r.UniversalEvent
		if evt.SchemaVersion != "1.0" {
			t.Errorf("expected SchemaVersion '1.0', got %q", evt.SchemaVersion)
		}
		if evt.Event.Action != "deny" {
			t.Errorf("expected Action 'deny', got %q", evt.Event.Action)
		}
		if evt.Network == nil {
			t.Fatalf("expected non-nil network info")
		}
		if evt.Network.Protocol != "TCP" {
			t.Errorf("expected Protocol 'TCP', got %q", evt.Network.Protocol)
		}
		if evt.Network.SrcIP != "192.168.1.20" {
			t.Errorf("expected SrcIP '192.168.1.20', got %q", evt.Network.SrcIP)
		}
		if evt.Network.DstIP != "10.0.0.15" {
			t.Errorf("expected DstIP '10.0.0.15', got %q", evt.Network.DstIP)
		}
		if evt.Network.SrcPort == nil || *evt.Network.SrcPort != 54321 {
			t.Errorf("expected SrcPort 54321, got %v", evt.Network.SrcPort)
		}
		if evt.Network.DstPort == nil || *evt.Network.DstPort != 443 {
			t.Errorf("expected DstPort 443, got %v", evt.Network.DstPort)
		}
	}
}

// ── Failure paths through the full ingestion → Redis → worker pipeline ───────

// buildPipeline wires the ingestion handler and worker over in-memory
// implementations of every external dependency.
func buildPipeline(t *testing.T) (*ingestion.Handler, *inMemoryBuffer, *worker.Worker, *normalized.MemoryStore, *quarantine.MemoryStore, *raw.MemoryRawStore) {
	t.Helper()

	rawBuf := &inMemoryBuffer{}
	rawStore := raw.NewMemoryRawStore()
	normalizedStore := normalized.NewMemoryStore()
	quarantineStore := quarantine.NewMemoryStore()
	idempotency := buffer.NewMemoryIdempotencyStore()

	registry := parsing.NewRegistry()
	registry.Register(parsers.NewSyslogParser())
	registry.Register(parsers.NewJSONParser())
	registry.Register(parsers.NewCSVParser())

	validator, err := validation.NewValidator("")
	if err != nil {
		t.Fatalf("failed to create validator: %v", err)
	}

	w := worker.NewWorker(
		rawBuf,
		idempotency,
		rawStore,
		detection.NewDetector(),
		parsing.NewEngine(registry),
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
		},
	)

	return ingestion.NewHandler(ingestion.NewService(rawBuf, "raw_events")),
		rawBuf, w, normalizedStore, quarantineStore, rawStore
}

// ingest posts one payload through the HTTP handler and returns the event_id.
func ingest(t *testing.T, handler *ingestion.Handler, format, payload string) string {
	t.Helper()

	reqBody := ingestion.IngestRequest{
		Format:  format,
		Source:  "firewall-01",
		Payload: payload,
	}
	reqBytes, _ := json.Marshal(reqBody)
	req := httptest.NewRequest(http.MethodPost, "/ingest", bytes.NewBuffer(reqBytes))
	rec := httptest.NewRecorder()
	handler.HandleIngest(rec, req)

	if rec.Code != http.StatusAccepted {
		t.Fatalf("expected 202 Accepted, got %d: %s", rec.Code, rec.Body.String())
	}

	var resp ingestion.IngestResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to decode ingest response: %v", err)
	}

	return resp.EventID
}

// waitForAck polls until the buffer has ACKed exactly one message.
func waitForAck(t *testing.T, buf *inMemoryBuffer) {
	t.Helper()

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) && len(buf.ackedIDs()) == 0 {
		time.Sleep(2 * time.Millisecond)
	}
}

// waitForQuarantine polls until the event appears in the quarantine store.
func waitForQuarantine(t *testing.T, store *quarantine.MemoryStore, eventID string) *quarantine.Entry {
	t.Helper()

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if entry, err := store.Get(context.Background(), eventID); err == nil {
			return entry
		}
		time.Sleep(2 * time.Millisecond)
	}

	t.Fatalf("timed out waiting for %s to be quarantined", eventID)
	return nil
}

// TestParseFailurePath_E2E — a malformed payload must be quarantined and the
// Redis message ACKed, so the poison pill does not block the stream.
func TestParseFailurePath_E2E(t *testing.T) {
	handler, rawBuf, w, normalizedStore, quarantineStore, _ := buildPipeline(t)

	eventID := ingest(t, handler, "json", `{"broken": `)

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	go func() { _ = w.Start(ctx) }()

	entry := waitForQuarantine(t, quarantineStore, eventID)
	if entry.Stage != string(failure.StageParsing) {
		t.Errorf("expected stage %q, got %q", failure.StageParsing, entry.Stage)
	}
	if entry.Type != failure.TypeParseFailed {
		t.Errorf("expected type %q, got %q", failure.TypeParseFailed, entry.Type)
	}
	if entry.Message == "" || entry.RawObjectKey == "" {
		t.Errorf("expected the quarantine entry to carry an error and a raw reference: %+v", entry)
	}

	// The original Redis message is ACKed: it is not left pending forever.
	waitForAck(t, rawBuf)
	if acked := rawBuf.ackedIDs(); len(acked) != 1 {
		t.Errorf("expected the quarantined message to be ACKed, got %v", acked)
	}

	if count, _ := normalizedStore.Count(context.Background()); count != 0 {
		t.Errorf("expected no normalized records for an unparseable event, got %d", count)
	}
}

// TestValidationFailurePath_E2E — an event that parses and normalizes but
// violates the Universal Event schema must be quarantined, not dropped.
func TestValidationFailurePath_E2E(t *testing.T) {
	handler, rawBuf, w, normalizedStore, quarantineStore, _ := buildPipeline(t)

	// src_port 999999 exceeds the schema's maximum of 65535.
	eventID := ingest(t, handler, "json",
		`{"timestamp":"2026-08-28T18:30:12Z","firewall":{"action":"deny","protocol":"TCP"},`+
			`"src_ip":"192.168.1.20","src_port":999999}`)

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	go func() { _ = w.Start(ctx) }()

	entry := waitForQuarantine(t, quarantineStore, eventID)
	if entry.Stage != string(failure.StageValidation) {
		t.Errorf("expected stage %q, got %q", failure.StageValidation, entry.Stage)
	}
	if entry.Type != failure.TypeValidationFailed {
		t.Errorf("expected type %q, got %q", failure.TypeValidationFailed, entry.Type)
	}

	waitForAck(t, rawBuf)
	if acked := rawBuf.ackedIDs(); len(acked) != 1 {
		t.Errorf("expected the invalid event to be ACKed after quarantine, got %v", acked)
	}

	if count, _ := normalizedStore.Count(context.Background()); count != 0 {
		t.Errorf("expected no normalized records for an invalid event, got %d", count)
	}
}

// TestDuplicateDeliveryPath_E2E — the same event submitted twice must produce
// exactly one normalized record.
func TestDuplicateDeliveryPath_E2E(t *testing.T) {
	handler, _, w, normalizedStore, quarantineStore, _ := buildPipeline(t)

	payload, err := os.ReadFile("../samples/syslog/sample.log")
	if err != nil {
		t.Fatalf("failed to read sample: %v", err)
	}

	eventID := ingest(t, handler, "syslog", string(payload))

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	go func() { _ = w.Start(ctx) }()

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if count, _ := normalizedStore.Count(context.Background()); count == 1 {
			break
		}
		time.Sleep(2 * time.Millisecond)
	}

	// Re-deliver the identical event (same event_id) through a second worker
	// sharing the same stores — the idempotency path must skip the side-effects.
	rawBuf2 := &inMemoryBuffer{messages: []buffer.RawMessage{{
		ID: "msg-duplicate",
		Event: models.RawEvent{
			EventID:    eventID,
			ReceivedAt: time.Now().UTC().Format(time.RFC3339),
			Format:     "syslog",
			Source:     "firewall-01",
			Payload:    string(payload),
		},
	}}}

	registry := parsing.NewRegistry()
	registry.Register(parsers.NewSyslogParser())
	validator, err := validation.NewValidator("")
	if err != nil {
		t.Fatalf("validator: %v", err)
	}
	w2 := worker.NewWorker(
		rawBuf2, buffer.NewMemoryIdempotencyStore(), raw.NewMemoryRawStore(),
		detection.NewDetector(),
		parsing.NewEngine(registry), normalization.NewNormalizer(), validator,
		worker.Config{
			StreamName:      "raw_events",
			GroupName:       "test-group",
			ConsumerName:    "test-worker-2",
			NormalizedStore: normalizedStore,
			QuarantineStore: quarantineStore,
		},
	)

	ctx2, cancel2 := context.WithTimeout(context.Background(), time.Second)
	defer cancel2()
	go func() { _ = w2.Start(ctx2) }()

	time.Sleep(200 * time.Millisecond)

	count, err := normalizedStore.Count(context.Background())
	if err != nil {
		t.Fatalf("count failed: %v", err)
	}
	if count != 1 {
		t.Errorf("expected exactly 1 normalized record after a duplicate delivery, got %d", count)
	}
	if qCount, _ := quarantineStore.Count(context.Background()); qCount != 0 {
		t.Errorf("expected no quarantine entries for a healthy duplicate, got %d", qCount)
	}
	if acked := rawBuf2.ackedIDs(); len(acked) != 1 {
		t.Errorf("expected the duplicate to be ACKed, got %v", acked)
	}
}
