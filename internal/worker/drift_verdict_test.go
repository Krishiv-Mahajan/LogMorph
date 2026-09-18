package worker

import (
	"bytes"
	"context"
	"log"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/Krishiv-Mahajan/LogMorph/internal/buffer"
	"github.com/Krishiv-Mahajan/LogMorph/internal/detection"
	"github.com/Krishiv-Mahajan/LogMorph/internal/drift"
	"github.com/Krishiv-Mahajan/LogMorph/internal/models"
	"github.com/Krishiv-Mahajan/LogMorph/internal/parsing"
	"github.com/Krishiv-Mahajan/LogMorph/internal/parsing/parsers"
	"github.com/Krishiv-Mahajan/LogMorph/internal/registry"
	"github.com/Krishiv-Mahajan/LogMorph/internal/storage/normalized"
	"github.com/Krishiv-Mahajan/LogMorph/internal/storage/quarantine"
	"github.com/Krishiv-Mahajan/LogMorph/internal/storage/raw"
)

// These tests pin the consolidation: the worker must produce exactly ONE drift
// verdict, from the schema drift engine, and everything downstream must read
// that one result.

// realParserCatalog exposes the shipped parser descriptors as a drift catalog.
func realParserCatalog() *parsing.Registry {
	parserRegistry := parsing.NewRegistry()
	parserRegistry.Register(parsers.NewSyslogParser())
	parserRegistry.Register(parsers.NewJSONParser())
	parserRegistry.Register(parsers.NewCSVParser())
	return parserRegistry
}

// newVerdictWorker builds a worker with a registry-backed drift analyzer over
// fresh in-memory stores.
func newVerdictWorker(t *testing.T, registryStore registry.Store) (*Worker, *normalized.MemoryStore, *quarantine.MemoryStore) {
	t.Helper()

	normalizedStore := normalized.NewMemoryStore()
	quarantineStore := quarantine.NewMemoryStore()

	w, err := setupTestWorkerWithStores(
		&mockWorkerBuffer{}, raw.NewMemoryRawStore(), buffer.NewMemoryIdempotencyStore(),
		normalizedStore, quarantineStore,
		Config{DriftAnalyzer: drift.NewEngine(registryStore, realParserCatalog())},
	)
	if err != nil {
		t.Fatalf("failed to build worker: %v", err)
	}

	return w, normalizedStore, quarantineStore
}

// analyzeEvent runs one event through the pipeline and returns the result.
func analyzeEvent(t *testing.T, w *Worker, format, source, payload string) *PipelineResult {
	t.Helper()

	res, err := w.ProcessSingleEvent(context.Background(), models.RawEvent{
		EventID:    "evt-verdict",
		ReceivedAt: time.Now().UTC().Format(time.RFC3339),
		Format:     format,
		Source:     source,
		Payload:    payload,
	})
	if err != nil {
		t.Fatalf("expected the event to process, got: %v", err)
	}
	if res.SchemaDrift == nil {
		t.Fatal("expected a schema drift verdict on the result")
	}

	return res
}

func TestSingleDriftVerdict_StableEvent(t *testing.T) {
	w, _, _ := newVerdictWorker(t, registry.NewMemoryStore())

	const payload = `{"timestamp":"2026-08-28T18:30:12Z","firewall":{"action":"deny","protocol":"TCP"}}`
	res := analyzeEvent(t, w, "json", "fw-stable", payload)

	if res.SchemaDrift.Classification != models.DriftStatusStable {
		t.Errorf("expected a stable verdict, got %q (%s)", res.SchemaDrift.Classification, res.SchemaDrift.Reason)
	}
	if res.SchemaDrift.Adapted {
		t.Error("a stable event must not adapt the mapping")
	}
	if res.SchemaDrift.EscalationRequired {
		t.Error("a stable event must not escalate")
	}

	// Exactly one verdict: the provenance records the schema drift classification
	// and nothing else can have supplied it.
	if res.Provenance.DriftStatus != string(res.SchemaDrift.Classification) {
		t.Errorf("expected provenance drift %q to match the schema verdict %q",
			res.Provenance.DriftStatus, res.SchemaDrift.Classification)
	}
	if res.Provenance.DriftStatus != string(models.DriftStatusStable) {
		t.Errorf("expected provenance to record stable, got %q", res.Provenance.DriftStatus)
	}
}

func TestSingleDriftVerdict_MinorDriftEvent(t *testing.T) {
	registryStore := registry.NewMemoryStore()
	w, _, _ := newVerdictWorker(t, registryStore)

	// Establish the source's base mapping.
	analyzeEvent(t, w, "json", "fw-minor", `{"timestamp":"2026-08-28T18:30:12Z"}`)

	res := analyzeEvent(t, w, "json", "fw-minor",
		`{"timestamp":"2026-08-28T18:30:12Z","device_uuid":"fw-9f2c"}`)

	if res.SchemaDrift.Classification != models.DriftStatusMinorDrift {
		t.Errorf("expected minor drift, got %q (%s)", res.SchemaDrift.Classification, res.SchemaDrift.Reason)
	}
	if !res.SchemaDrift.Adapted {
		t.Error("expected the additive field to be adapted")
	}
	if res.SchemaDrift.EscalationRequired {
		t.Error("a safe adaptation must not escalate")
	}
	if res.Provenance.DriftStatus != string(models.DriftStatusMinorDrift) {
		t.Errorf("expected provenance to record minor_drift, got %q", res.Provenance.DriftStatus)
	}
	if res.Provenance.MappingVersion != res.Mapping.MappingVersion {
		t.Error("expected provenance to name the mapping version that processed the event")
	}
}

// TestSingleDriftVerdict_MajorDriftEscalates — the drift recorded here is
// major_drift even though the format is recognised with full confidence, which
// is precisely what the removed format-level detector would have called stable.
// It proves the recorded verdict comes from the schema drift path.
func TestSingleDriftVerdict_MajorDriftEscalates(t *testing.T) {
	w, _, _ := newVerdictWorker(t, registry.NewMemoryStore())

	// The required timestamp disappears.
	res := analyzeEvent(t, w, "json", "fw-major", `{"firewall":{"action":"deny"}}`)

	if res.SchemaDrift.Classification != models.DriftStatusMajorDrift {
		t.Fatalf("expected major drift, got %q (%s)", res.SchemaDrift.Classification, res.SchemaDrift.Reason)
	}
	if !res.SchemaDrift.EscalationRequired {
		t.Error("expected unsafe drift to escalate")
	}
	if res.SchemaDrift.Adapted {
		t.Error("an unsafe change must never be adapted")
	}
	if res.Provenance.DriftStatus != string(models.DriftStatusMajorDrift) {
		t.Errorf("expected provenance to record major_drift, got %q", res.Provenance.DriftStatus)
	}
}

// TestSingleDriftVerdict_UnknownFormatEscalates covers the other half of
// EscalationRequired.
func TestSingleDriftVerdict_UnknownFormatEscalates(t *testing.T) {
	w, _, _ := newVerdictWorker(t, registry.NewMemoryStore())

	// No parser contract exists for this format, so the event cannot be mapped.
	res, _ := w.ProcessSingleEvent(context.Background(), models.RawEvent{
		EventID: "evt-unknown", Format: "xml", Source: "app-1",
		Payload: "<log><action>deny</action></log>",
	})

	if res.SchemaDrift == nil {
		t.Fatal("expected a drift verdict even for an unmapped format")
	}
	if res.SchemaDrift.Classification != models.DriftStatusUnknown {
		t.Errorf("expected unknown, got %q", res.SchemaDrift.Classification)
	}
	if !res.SchemaDrift.EscalationRequired {
		t.Error("expected an unmapped format to escalate")
	}
	if res.Provenance.DriftStatus != string(models.DriftStatusUnknown) {
		t.Errorf("expected provenance to record unknown, got %q", res.Provenance.DriftStatus)
	}
}

// TestDriftSignalSurvivesLaterFailure — the drift verdict is captured before
// parsing, so an event that goes on to fail still carries its drift signal into
// the quarantine record. This is the signal the removed format-level alert used
// to be the only source of.
func TestDriftSignalSurvivesLaterFailure(t *testing.T) {
	tests := []struct {
		name    string
		source  string
		payload string
	}{
		{
			name:    "fails validation",
			source:  "fw-late-validation",
			payload: `{"src_port":999999}`, // required timestamp absent, port out of range
		},
		{
			name:    "fails parsing",
			source:  "fw-late-parse",
			payload: `[1,2,3]`, // a JSON array cannot be parsed into the event contract
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w, normalizedStore, quarantineStore := newVerdictWorker(t, registry.NewMemoryStore())

			msg := jsonMsg("msg-late", "evt_late_failure", tt.payload)
			msg.Event.Source = tt.source

			res, err := w.ProcessSingleEvent(context.Background(), msg.Event)
			if err == nil {
				t.Fatal("expected the event to fail")
			}

			// The verdict exists on the result even though processing failed.
			if res.SchemaDrift == nil {
				t.Fatal("expected a drift verdict on a failed event")
			}
			if res.SchemaDrift.Classification != models.DriftStatusMajorDrift {
				t.Fatalf("expected major drift, got %q (%s)", res.SchemaDrift.Classification, res.SchemaDrift.Reason)
			}
			if !res.SchemaDrift.EscalationRequired {
				t.Error("expected escalation to be required")
			}

			// And it reaches the quarantine record through the worker loop.
			loopQuarantine(t, w, msg, quarantineStore)

			entry, err := quarantineStore.Get(context.Background(), "evt_late_failure")
			if err != nil {
				t.Fatalf("expected the event to be quarantined: %v", err)
			}
			if entry.Provenance.DriftStatus != string(models.DriftStatusMajorDrift) {
				t.Errorf("expected the quarantine record to carry major_drift, got %q", entry.Provenance.DriftStatus)
			}
			if entry.Provenance.ParserID != "generic_json" {
				t.Errorf("expected the quarantine record to name the parser, got %q", entry.Provenance.ParserID)
			}
			if entry.Provenance.MappingID == "" || entry.Provenance.MappingVersion == 0 {
				t.Error("expected the quarantine record to name the mapping version in force")
			}
			if count, _ := normalizedStore.Count(context.Background()); count != 0 {
				t.Errorf("expected no normalized records, got %d", count)
			}
		})
	}
}

// loopQuarantine runs the message through the worker loop so the quarantine
// write path (which the direct call does not exercise) is covered.
func loopQuarantine(t *testing.T, w *Worker, msg buffer.RawMessage, quarantineStore *quarantine.MemoryStore) {
	t.Helper()

	// A fresh worker over the same stores, driven by the loop.
	loopBuf := &mockWorkerBuffer{messages: []buffer.RawMessage{msg}}
	looping, err := setupTestWorkerWithStores(
		loopBuf, raw.NewMemoryRawStore(), buffer.NewMemoryIdempotencyStore(),
		normalized.NewMemoryStore(), quarantineStore,
		Config{DriftAnalyzer: drift.NewEngine(registry.NewMemoryStore(), realParserCatalog())},
	)
	if err != nil {
		t.Fatalf("failed to build the loop worker: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 400*time.Millisecond)
	defer cancel()
	_ = looping.Start(ctx)

	waitFor(t, time.Second, func() bool {
		count, _ := quarantineStore.Count(context.Background())
		return count >= 1
	}, "the event to be quarantined")
}

// TestEscalationAlertEmittedFromSchemaDrift — the alert is driven by the
// authoritative verdict: emitted for major_drift and unknown, silent for stable.
func TestEscalationAlertEmittedFromSchemaDrift(t *testing.T) {
	var captured bytes.Buffer

	original := log.Writer()
	log.SetOutput(&captured)
	defer log.SetOutput(original)

	w, _, _ := newVerdictWorker(t, registry.NewMemoryStore())

	// Stable: no alert.
	analyzeEvent(t, w, "json", "fw-alert", `{"timestamp":"2026-08-28T18:30:12Z"}`)
	if strings.Contains(captured.String(), "stage=drift outcome=alert") {
		t.Errorf("expected no drift alert for a stable event, got:\n%s", captured.String())
	}

	// Major drift: alert, naming the authoritative status.
	captured.Reset()
	analyzeEvent(t, w, "json", "fw-alert", `{"firewall":{"action":"deny"}}`)
	alert := captured.String()
	if !strings.Contains(alert, "stage=drift outcome=alert") {
		t.Errorf("expected a drift alert for a major drift event, got:\n%s", alert)
	}
	if !strings.Contains(alert, "status=major_drift") {
		t.Errorf("expected the alert to carry the schema drift status, got:\n%s", alert)
	}

	// Unknown: alert as well.
	captured.Reset()
	_, _ = w.ProcessSingleEvent(context.Background(), models.RawEvent{
		EventID: "evt-alert-unknown", Format: "xml", Source: "app-1", Payload: "<log/>",
	})
	if !strings.Contains(captured.String(), "status=unknown") {
		t.Errorf("expected an alert for an unmapped format, got:\n%s", captured.String())
	}
}

// TestWorkerHasExactlyOneDriftDependency is the structural guard: the worker
// cannot reach a second drift implementation, because no field or configuration
// value carries one. It also asserts the schema drift analyzer IS wired, so the
// check cannot pass by accident if drift is removed entirely.
func TestWorkerHasExactlyOneDriftDependency(t *testing.T) {
	legacyDetector := reflect.TypeOf((*detection.DriftDetector)(nil)).Elem()
	schemaAnalyzer := reflect.TypeOf((*drift.Analyzer)(nil)).Elem()

	hasField := func(structType reflect.Type, iface reflect.Type) bool {
		for i := 0; i < structType.NumField(); i++ {
			if structType.Field(i).Type.Implements(iface) {
				return true
			}
		}
		return false
	}

	workerType := reflect.TypeOf(Worker{})
	configType := reflect.TypeOf(Config{})

	for _, target := range []struct {
		name       string
		structType reflect.Type
	}{
		{"Worker", workerType},
		{"Config", configType},
	} {
		if hasField(target.structType, legacyDetector) {
			t.Errorf("%s must not carry a detection.DriftDetector: the worker has one drift authority", target.name)
		}
		if target.name == "Worker" && !hasField(target.structType, schemaAnalyzer) {
			t.Error("Worker must carry the drift.Analyzer: it is the single drift authority")
		}
		if target.name == "Config" && !hasField(target.structType, schemaAnalyzer) {
			t.Error("Config must accept a drift.Analyzer")
		}
	}
}

// TestProcessSingleEventDoesNotUseALegacyDetector — behavioural half of the
// guard above: a format the old detector would have called stable (recognised
// format, full-confidence hint) is recorded with the schema verdict instead.
func TestProcessSingleEventDoesNotUseALegacyDetector(t *testing.T) {
	// Sanity-check the premise: the old detector considers this input stable.
	detectionRes := detection.NewDetector().Detect(`{"firewall":{"action":"deny"}}`, "json")
	legacy, err := detection.NewDriftDetector().Analyze(context.Background(),
		models.RawEvent{Payload: `{"firewall":{"action":"deny"}}`}, detectionRes)
	if err != nil {
		t.Fatalf("legacy detector failed: %v", err)
	}
	if legacy.Status != models.DriftStatusStable {
		t.Fatalf("test premise broken: expected the legacy detector to report stable, got %q", legacy.Status)
	}

	// The worker records the schema verdict, not the legacy one.
	w, _, _ := newVerdictWorker(t, registry.NewMemoryStore())
	res := analyzeEvent(t, w, "json", "fw-legacy-check", `{"firewall":{"action":"deny"}}`)

	if res.SchemaDrift.Classification == legacy.Status {
		t.Fatalf("expected the schema verdict (%q) to differ from the legacy verdict (%q) for this input",
			res.SchemaDrift.Classification, legacy.Status)
	}
	if res.Provenance.DriftStatus != string(models.DriftStatusMajorDrift) {
		t.Errorf("expected the recorded verdict to be major_drift, got %q", res.Provenance.DriftStatus)
	}
}
