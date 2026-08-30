package tests

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/Krishiv-Mahajan/LogMorph/internal/detection"
	"github.com/Krishiv-Mahajan/LogMorph/internal/ingestion"
	"github.com/Krishiv-Mahajan/LogMorph/internal/normalization"
	"github.com/Krishiv-Mahajan/LogMorph/internal/parsing"
	"github.com/Krishiv-Mahajan/LogMorph/internal/parsing/parsers"
	"github.com/Krishiv-Mahajan/LogMorph/internal/status"
	"github.com/Krishiv-Mahajan/LogMorph/internal/storage/raw"
	"github.com/Krishiv-Mahajan/LogMorph/internal/validation"
	"github.com/Krishiv-Mahajan/LogMorph/internal/worker"
)

func TestStatusPipeline_EndToEnd(t *testing.T) {
	rawBuf := &inMemoryBuffer{}
	rawStore := raw.NewMemoryRawStore()
	statusStore := status.NewMemoryStatusStore()

	// Ingestion Setup with Status
	ingestService := ingestion.NewServiceWithStatus(rawBuf, "raw_events", statusStore)
	ingestHandler := ingestion.NewHandlerWithStatus(ingestService, statusStore)

	mux := http.NewServeMux()
	ingestHandler.RegisterRoutes(mux)

	// Worker Setup with Status
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
		nil, // idempotency nil in test
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
			StatusStore:  statusStore,
		},
	)

	// ── 1. Test POST /ingest (Syslog payload) ──
	syslogPayload := "Aug 28 18:30:12 firewall kernel: SRC=192.168.1.10 DST=10.0.0.5 PROTO=TCP SPT=443 DPT=8080 ACTION=ALLOW"
	ingestReq := ingestion.IngestRequest{
		Format:  "syslog",
		Source:  "firewall",
		Payload: syslogPayload,
	}
	reqBytes, _ := json.Marshal(ingestReq)
	req := httptest.NewRequest(http.MethodPost, "/ingest", bytes.NewBuffer(reqBytes))
	rec := httptest.NewRecorder()

	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusAccepted {
		t.Fatalf("expected 202 Accepted, got %d: %s", rec.Code, rec.Body.String())
	}

	var ingestResp ingestion.IngestResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &ingestResp); err != nil {
		t.Fatalf("failed to decode ingest response: %v", err)
	}

	if ingestResp.EventID == "" || ingestResp.Status != "accepted" {
		t.Fatalf("invalid ingest response: %+v", ingestResp)
	}

	eventID := ingestResp.EventID
	t.Logf("Ingested event ID: %s", eventID)

	// ── 2. Query Status Immediately After Ingestion ──
	statusReq := httptest.NewRequest(http.MethodGet, "/events/"+eventID+"/status", nil)
	statusRec := httptest.NewRecorder()
	mux.ServeHTTP(statusRec, statusReq)

	if statusRec.Code != http.StatusOK {
		t.Fatalf("expected 200 OK for initial status, got %d", statusRec.Code)
	}

	var initialStatus status.EventStatus
	if err := json.Unmarshal(statusRec.Body.Bytes(), &initialStatus); err != nil {
		t.Fatalf("failed to decode status: %v", err)
	}

	if initialStatus.Status != status.StatusProcessing {
		t.Errorf("expected initial status Processing, got %s", initialStatus.Status)
	}
	if initialStatus.Stages[status.StageIngestion].State != status.StateSuccess {
		t.Errorf("expected ingestion state success, got %s", initialStatus.Stages[status.StageIngestion].State)
	}
	if initialStatus.Stages[status.StageDetection].State != status.StateIdle {
		t.Errorf("expected detection state idle initially, got %s", initialStatus.Stages[status.StageDetection].State)
	}

	t.Logf("Initial status JSON:\n%s", statusRec.Body.String())

	// ── 3. Process Event via Worker ──
	if len(rawBuf.messages) == 0 {
		t.Fatalf("expected message buffered")
	}
	msg := rawBuf.messages[0]
	rawBuf.messages = nil

	_, procErr := w.ProcessSingleEvent(context.Background(), msg.Event)
	if procErr != nil {
		t.Fatalf("worker processing failed: %v", procErr)
	}

	// ── 4. Query Final Status After Processing ──
	finalStatusRec := httptest.NewRecorder()
	statusReq2 := httptest.NewRequest(http.MethodGet, "/events/"+eventID+"/status", nil)
	mux.ServeHTTP(finalStatusRec, statusReq2)

	if finalStatusRec.Code != http.StatusOK {
		t.Fatalf("expected 200 OK for final status, got %d", finalStatusRec.Code)
	}

	var finalStatus status.EventStatus
	if err := json.Unmarshal(finalStatusRec.Body.Bytes(), &finalStatus); err != nil {
		t.Fatalf("failed to decode final status: %v", err)
	}

	if finalStatus.Status != status.StatusParsed {
		t.Errorf("expected final status Parsed, got %s", finalStatus.Status)
	}
	if finalStatus.DriftDetected {
		t.Errorf("expected DriftDetected false for standard syslog")
	}
	if finalStatus.UniversalEvent == nil {
		t.Fatalf("expected UniversalEvent in final status")
	}

	// Verify all stages are success
	for _, stageName := range []string{
		status.StageIngestion,
		status.StageDetection,
		status.StageDrift,
		status.StageParsing,
		status.StageNormalization,
		status.StageValidation,
	} {
		s := finalStatus.Stages[stageName]
		if s.State != status.StateSuccess {
			t.Errorf("expected stage %s to be success, got %s", stageName, s.State)
		}
	}

	t.Logf("Final status JSON:\n%s", finalStatusRec.Body.String())

	// ── 5. Test 404 for Non-Existent Event ──
	rec404 := httptest.NewRecorder()
	req404 := httptest.NewRequest(http.MethodGet, "/events/evt_nonexistent/status", nil)
	mux.ServeHTTP(rec404, req404)

	if rec404.Code != http.StatusNotFound {
		t.Errorf("expected 404 Not Found, got %d", rec404.Code)
	}
	t.Logf("404 response JSON:\n%s", rec404.Body.String())

	// ── 6. Test Error / Unknown Format Event ──
	badIngestReq := ingestion.IngestRequest{
		Payload: "INVALID_UNPARSEABLE_DATA_12345",
	}
	badReqBytes, _ := json.Marshal(badIngestReq)
	badReq := httptest.NewRequest(http.MethodPost, "/ingest", bytes.NewBuffer(badReqBytes))
	badRec := httptest.NewRecorder()
	mux.ServeHTTP(badRec, badReq)

	var badIngestResp ingestion.IngestResponse
	_ = json.Unmarshal(badRec.Body.Bytes(), &badIngestResp)
	badEventID := badIngestResp.EventID

	if len(rawBuf.messages) > 0 {
		badMsg := rawBuf.messages[0]
		rawBuf.messages = nil
		_, _ = w.ProcessSingleEvent(context.Background(), badMsg.Event)
	}

	badStatusRec := httptest.NewRecorder()
	badStatusReq := httptest.NewRequest(http.MethodGet, "/events/"+badEventID+"/status", nil)
	mux.ServeHTTP(badStatusRec, badStatusReq)

	var badStatus status.EventStatus
	_ = json.Unmarshal(badStatusRec.Body.Bytes(), &badStatus)

	if badStatus.Status != status.StatusError {
		t.Errorf("expected status Error for bad payload, got %s", badStatus.Status)
	}
	if !badStatus.DriftDetected {
		t.Errorf("expected DriftDetected true for unknown format")
	}
	if badStatus.Stages[status.StageParsing].State != status.StateError {
		t.Errorf("expected parsing stage error, got %s", badStatus.Stages[status.StageParsing].State)
	}
	if badStatus.Stages[status.StageNormalization].State != status.StateIdle {
		t.Errorf("expected normalization stage to remain idle after parsing failure, got %s", badStatus.Stages[status.StageNormalization].State)
	}

	t.Logf("Bad status JSON:\n%s", badStatusRec.Body.String())
}
