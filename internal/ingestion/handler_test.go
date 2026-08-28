package ingestion

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/Krishiv-Mahajan/LogMorph/internal/buffer"
	"github.com/Krishiv-Mahajan/LogMorph/internal/models"
)

type mockRawBuffer struct {
	published []*models.RawEvent
}

func (m *mockRawBuffer) PublishRaw(ctx context.Context, stream string, event *models.RawEvent) (string, error) {
	m.published = append(m.published, event)
	return "mock_raw_msg_1", nil
}

func (m *mockRawBuffer) EnsureGroup(ctx context.Context, stream string, group string) error {
	return nil
}

func (m *mockRawBuffer) ReadGroup(ctx context.Context, stream, group, consumer string, count int64, block time.Duration) ([]buffer.RawMessage, error) {
	return nil, nil
}

func (m *mockRawBuffer) Ack(ctx context.Context, stream, group string, ids ...string) error {
	return nil
}

func (m *mockRawBuffer) ClaimPending(ctx context.Context, stream, group, consumer string, minIdleTime time.Duration, count int64) ([]buffer.RawMessage, error) {
	return nil, nil
}

func (m *mockRawBuffer) Ping(ctx context.Context) error {
	return nil
}

func (m *mockRawBuffer) Close() error {
	return nil
}

func TestHandler_IngestAndHealth(t *testing.T) {
	mockBuf := &mockRawBuffer{}
	service := NewService(mockBuf, "raw_events")
	handler := NewHandler(service)

	// Test GET /health
	recHealth := httptest.NewRecorder()
	reqHealth := httptest.NewRequest(http.MethodGet, "/health", nil)
	handler.HandleHealth(recHealth, reqHealth)
	if recHealth.Code != http.StatusOK {
		t.Errorf("expected 200 OK, got %d", recHealth.Code)
	}

	// Test POST /ingest
	body := `{"format":"syslog","source":"firewall-01","payload":"Aug 28 18:30:12 firewall01 DENY TCP SRC=192.168.1.20:54321 DST=10.0.0.15:443"}`
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

	if len(mockBuf.published) != 1 {
		t.Fatalf("expected 1 published raw event, got %d", len(mockBuf.published))
	}
	if mockBuf.published[0].Payload != "Aug 28 18:30:12 firewall01 DENY TCP SRC=192.168.1.20:54321 DST=10.0.0.15:443" {
		t.Errorf("payload corrupted during ingestion: %s", mockBuf.published[0].Payload)
	}
}

func TestHandler_EmptyPayload(t *testing.T) {
	service := NewService(nil, "")
	handler := NewHandler(service)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/ingest", bytes.NewBufferString(`{"payload":""}`))
	handler.HandleIngest(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("expected 400 Bad Request, got %d", rec.Code)
	}
}
