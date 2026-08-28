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

	goredis "github.com/redis/go-redis/v9"

	"github.com/Krishiv-Mahajan/LogMorph/internal/detection"
	"github.com/Krishiv-Mahajan/LogMorph/internal/ingestion"
	"github.com/Krishiv-Mahajan/LogMorph/internal/models"
	"github.com/Krishiv-Mahajan/LogMorph/internal/normalization"
	"github.com/Krishiv-Mahajan/LogMorph/internal/normalization/parsers"
	"github.com/Krishiv-Mahajan/LogMorph/internal/validation"
)

// mockStreamClient captures published events in-memory for testing
type mockStreamClient struct {
	published []*models.WorkerEvent
}

func (m *mockStreamClient) PublishEvent(ctx context.Context, stream string, event *models.WorkerEvent) (string, error) {
	m.published = append(m.published, event)
	return "mock_msg_1", nil
}

func (m *mockStreamClient) EnsureConsumerGroup(ctx context.Context, stream string, group string) error {
	return nil
}

func (m *mockStreamClient) ReadGroup(ctx context.Context, stream, group, consumer string, count int64, block time.Duration) ([]goredis.XMessage, error) {
	return nil, nil
}

func (m *mockStreamClient) Ack(ctx context.Context, stream, group string, ids ...string) error {
	return nil
}

func (m *mockStreamClient) Close() error {
	return nil
}

func (m *mockStreamClient) Ping(ctx context.Context) error {
	return nil
}

func setupTestPipeline() (*ingestion.Handler, *mockStreamClient, validation.Validator, error) {
	detector := detection.NewDetector()
	registry := normalization.NewRegistry()
	registry.Register(parsers.NewSyslogParser())
	registry.Register(parsers.NewJSONParser())
	registry.Register(parsers.NewCSVParser())

	normalizer := normalization.NewNormalizer(detector, registry)
	validator, err := validation.NewValidator("")
	if err != nil {
		return nil, nil, nil, err
	}

	mockStream := &mockStreamClient{}
	handler := ingestion.NewHandler(normalizer, validator, mockStream, "test_stream")
	return handler, mockStream, validator, nil
}

func TestEndToEndPipeline_HTTP(t *testing.T) {
	handler, mockStream, _, err := setupTestPipeline()
	if err != nil {
		t.Fatalf("failed to setup pipeline: %v", err)
	}

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

	for _, s := range samples {
		t.Run(s.name, func(t *testing.T) {
			content, err := os.ReadFile(s.samplePath)
			if err != nil {
				t.Fatalf("failed to read sample %s: %v", s.samplePath, err)
			}

			reqBody := ingestion.IngestRequest{
				Format:  s.hint,
				Source:  "test-fw",
				Payload: string(content),
			}
			bodyBytes, _ := json.Marshal(reqBody)

			req := httptest.NewRequest(http.MethodPost, "/ingest", bytes.NewBuffer(bodyBytes))
			req.Header.Set("Content-Type", "application/json")
			rec := httptest.NewRecorder()

			handler.HandleIngest(rec, req)

			if rec.Code != http.StatusAccepted {
				t.Fatalf("expected 202 Accepted, got %d: %s", rec.Code, rec.Body.String())
			}

			var resp ingestion.IngestResponse
			if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
				t.Fatalf("failed to unmarshal response: %v", err)
			}

			if resp.EventID == "" || resp.Status != "accepted" {
				t.Fatalf("invalid response body: %+v", resp)
			}
		})
	}

	if len(mockStream.published) != 3 {
		t.Fatalf("expected 3 published events in stream, got %d", len(mockStream.published))
	}

	// Verify Universal Event convergence across all 3 formats
	for _, published := range mockStream.published {
		evt := published.Event
		if evt.SchemaVersion != "1.0" {
			t.Errorf("expected schema_version '1.0', got %q", evt.SchemaVersion)
		}
		if evt.Event.Action != "deny" {
			t.Errorf("expected action 'deny', got %q", evt.Event.Action)
		}
		if evt.Network == nil {
			t.Fatalf("expected non-nil network info")
		}
		if evt.Network.Protocol != "TCP" {
			t.Errorf("expected protocol 'TCP', got %q", evt.Network.Protocol)
		}
		if evt.Network.SrcIP != "192.168.1.20" {
			t.Errorf("expected src_ip '192.168.1.20', got %q", evt.Network.SrcIP)
		}
		if evt.Network.DstIP != "10.0.0.15" {
			t.Errorf("expected dst_ip '10.0.0.15', got %q", evt.Network.DstIP)
		}
		if evt.Network.SrcPort == nil || *evt.Network.SrcPort != 54321 {
			t.Errorf("expected src_port 54321, got %v", evt.Network.SrcPort)
		}
		if evt.Network.DstPort == nil || *evt.Network.DstPort != 443 {
			t.Errorf("expected dst_port 443, got %v", evt.Network.DstPort)
		}
	}
}
