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
	handler := NewHandler(service, nil, nil)

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
	handler := NewHandler(service, nil, nil)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/ingest", bytes.NewBufferString(`{"payload":""}`))
	handler.HandleIngest(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("expected 400 Bad Request, got %d", rec.Code)
	}
}

func TestHandler_BatchIngest_Success(t *testing.T) {
	mockBuf := &mockRawBuffer{}
	service := NewService(mockBuf, "raw_events")
	handler := NewHandler(service, nil, nil)

	batchPayload := `[
		{"format":"syslog","source":"firewall-01","payload":"Aug 28 18:30:12 firewall01 DENY TCP SRC=10.0.0.1 DST=8.8.8.8"},
		{"format":"json","source":"waf-01","payload":"{\"action\":\"block\",\"ip\":\"1.2.3.4\"}"},
		{"format":"csv","source":"router-01","payload":"2026-08-28,router-01,drop,10.0.0.5,10.0.0.6"}
	]`

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/ingest/batch", bytes.NewBufferString(batchPayload))
	handler.HandleIngestBatch(rec, req)

	if rec.Code != http.StatusAccepted {
		t.Fatalf("expected 202 Accepted, got %d: %s", rec.Code, rec.Body.String())
	}

	var resp BatchIngestResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to decode batch response: %v", err)
	}

	if resp.Status != "accepted" {
		t.Errorf("expected status 'accepted', got %q", resp.Status)
	}
	if resp.Count != 3 {
		t.Errorf("expected count 3, got %d", resp.Count)
	}
	if len(resp.EventIDs) != 3 {
		t.Fatalf("expected 3 event IDs, got %d", len(resp.EventIDs))
	}

	// Verify all event IDs are distinct
	idSet := make(map[string]bool)
	for _, id := range resp.EventIDs {
		if id == "" {
			t.Errorf("empty event ID generated")
		}
		if idSet[id] {
			t.Errorf("duplicate event ID generated: %s", id)
		}
		idSet[id] = true
	}

	// Verify buffer received 3 raw events with exact payloads preserved
	if len(mockBuf.published) != 3 {
		t.Fatalf("expected 3 events published to buffer, got %d", len(mockBuf.published))
	}
	if mockBuf.published[0].Payload != "Aug 28 18:30:12 firewall01 DENY TCP SRC=10.0.0.1 DST=8.8.8.8" {
		t.Errorf("event 0 payload mismatch: %s", mockBuf.published[0].Payload)
	}
	if mockBuf.published[1].Payload != `{"action":"block","ip":"1.2.3.4"}` {
		t.Errorf("event 1 payload mismatch: %s", mockBuf.published[1].Payload)
	}
	if mockBuf.published[2].Payload != "2026-08-28,router-01,drop,10.0.0.5,10.0.0.6" {
		t.Errorf("event 2 payload mismatch: %s", mockBuf.published[2].Payload)
	}
}

func TestHandler_BatchIngest_ValidationErrors(t *testing.T) {
	service := NewService(nil, "")
	handler := NewHandler(service, nil, nil)

	tests := []struct {
		name       string
		body       string
		wantStatus int
	}{
		{
			name:       "empty batch array",
			body:       `[]`,
			wantStatus: http.StatusBadRequest,
		},
		{
			name:       "malformed JSON",
			body:       `[{not-valid-json`,
			wantStatus: http.StatusBadRequest,
		},
		{
			name:       "batch with empty payload in one item",
			body:       `[{"format":"syslog","source":"fw","payload":"valid"},{"format":"syslog","source":"fw","payload":""}]`,
			wantStatus: http.StatusBadRequest,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodPost, "/ingest/batch", bytes.NewBufferString(tc.body))
			handler.HandleIngestBatch(rec, req)

			if rec.Code != tc.wantStatus {
				t.Errorf("expected status %d, got %d (body: %s)", tc.wantStatus, rec.Code, rec.Body.String())
			}
		})
	}
}
