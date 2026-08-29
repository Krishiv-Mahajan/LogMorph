package tests

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/Krishiv-Mahajan/LogMorph/internal/buffer"
	"github.com/Krishiv-Mahajan/LogMorph/internal/detection"
	"github.com/Krishiv-Mahajan/LogMorph/internal/ingestion"
	"github.com/Krishiv-Mahajan/LogMorph/internal/models"
	"github.com/Krishiv-Mahajan/LogMorph/internal/normalization"
	"github.com/Krishiv-Mahajan/LogMorph/internal/parsing"
	"github.com/Krishiv-Mahajan/LogMorph/internal/parsing/parsers"
	"github.com/Krishiv-Mahajan/LogMorph/internal/storage/raw"
	"github.com/Krishiv-Mahajan/LogMorph/internal/validation"
	"github.com/Krishiv-Mahajan/LogMorph/internal/worker"
)

type inMemoryBuffer struct {
	messages []buffer.RawMessage
	acked    []string
}

func (b *inMemoryBuffer) PublishRaw(ctx context.Context, stream string, event *models.RawEvent) (string, error) {
	id := "msg_1"
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
	if len(b.messages) > 0 {
		msgs := b.messages
		b.messages = nil
		return msgs, nil
	}
	return nil, nil
}

func (b *inMemoryBuffer) Ack(ctx context.Context, stream, group string, ids ...string) error {
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

func TestFullTargetArchitecture_E2E(t *testing.T) {
	rawBuf := &inMemoryBuffer{}
	rawStore := raw.NewMemoryRawStore()

	// Ingestion Setup
	ingestService := ingestion.NewService(rawBuf, "raw_events")
	ingestHandler := ingestion.NewHandler(ingestService)

	// Worker Setup
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

	w := worker.NewWorker(
		rawBuf,
		buffer.NewMemoryIdempotencyStore(),
		rawStore,
		detector,
		driftDetector,
		parserEngine,
		normalizer,
		validator,
		worker.Config{
			StreamName:   "raw_events",
			GroupName:    "test-group",
			ConsumerName: "test-worker",
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
			if len(rawBuf.messages) == 0 {
				t.Fatalf("expected message buffered in Redis, found none")
			}
			rawMsg := rawBuf.messages[0]
			rawBuf.messages = nil // simulate consuming

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
