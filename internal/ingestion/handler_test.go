package ingestion

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	goredis "github.com/redis/go-redis/v9"

	"github.com/Krishiv-Mahajan/LogMorph/internal/detection"
	"github.com/Krishiv-Mahajan/LogMorph/internal/models"
	"github.com/Krishiv-Mahajan/LogMorph/internal/normalization"
	"github.com/Krishiv-Mahajan/LogMorph/internal/normalization/parsers"
	"github.com/Krishiv-Mahajan/LogMorph/internal/validation"
)

type mockStreamClient struct {
	published []*models.WorkerEvent
}

func (m *mockStreamClient) PublishEvent(ctx context.Context, stream string, event *models.WorkerEvent) (string, error) {
	m.published = append(m.published, event)
	return "mock_1", nil
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

func TestHandler_IngestAndHealth(t *testing.T) {
	detector := detection.NewDetector()
	registry := normalization.NewRegistry()
	registry.Register(parsers.NewSyslogParser())
	normalizer := normalization.NewNormalizer(detector, registry)
	validator, err := validation.NewValidator("")
	if err != nil {
		t.Fatalf("failed to create validator: %v", err)
	}

	mockStream := &mockStreamClient{}
	handler := NewHandler(normalizer, validator, mockStream, "normalized_events")

	// Health check test
	recHealth := httptest.NewRecorder()
	reqHealth := httptest.NewRequest(http.MethodGet, "/health", nil)
	handler.HandleHealth(recHealth, reqHealth)
	if recHealth.Code != http.StatusOK {
		t.Errorf("expected 200 OK for /health, got %d", recHealth.Code)
	}

	// Ingest test
	body := `{"payload": "Aug 28 18:30:12 firewall01 DENY TCP SRC=192.168.1.20:54321 DST=10.0.0.15:443"}`
	recIngest := httptest.NewRecorder()
	reqIngest := httptest.NewRequest(http.MethodPost, "/ingest", bytes.NewBufferString(body))
	handler.HandleIngest(recIngest, reqIngest)

	if recIngest.Code != http.StatusAccepted {
		t.Fatalf("expected 202 Accepted, got %d: %s", recIngest.Code, recIngest.Body.String())
	}

	var resp IngestResponse
	if err := json.Unmarshal(recIngest.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if resp.EventID == "" || resp.Status != "accepted" {
		t.Errorf("unexpected response: %+v", resp)
	}
}

func TestHandler_EmptyPayload(t *testing.T) {
	detector := detection.NewDetector()
	registry := normalization.NewRegistry()
	normalizer := normalization.NewNormalizer(detector, registry)
	validator, _ := validation.NewValidator("")

	handler := NewHandler(normalizer, validator, nil, "")
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/ingest", bytes.NewBufferString(`{"payload": ""}`))
	handler.HandleIngest(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("expected 400 Bad Request, got %d", rec.Code)
	}
}
