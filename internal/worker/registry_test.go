package worker

import (
	"context"
	"testing"
	"time"

	"github.com/Krishiv-Mahajan/LogMorph/internal/buffer"
	"github.com/Krishiv-Mahajan/LogMorph/internal/drift"
	"github.com/Krishiv-Mahajan/LogMorph/internal/models"
	"github.com/Krishiv-Mahajan/LogMorph/internal/parsing"
	"github.com/Krishiv-Mahajan/LogMorph/internal/parsing/parsers"
	"github.com/Krishiv-Mahajan/LogMorph/internal/registry"
	"github.com/Krishiv-Mahajan/LogMorph/internal/storage/normalized"
	"github.com/Krishiv-Mahajan/LogMorph/internal/storage/quarantine"
	"github.com/Krishiv-Mahajan/LogMorph/internal/storage/raw"
)

// buildRegistryEngine wires a drift engine over the real parser descriptors.
func buildRegistryEngine(store registry.Store) *drift.Engine {
	parserRegistry := parsing.NewRegistry()
	parserRegistry.Register(parsers.NewJSONParser())
	parserRegistry.Register(parsers.NewCSVParser())
	parserRegistry.Register(parsers.NewSyslogParser())

	return drift.NewEngine(store, parserRegistry)
}

// TestWorkerRecordsProvenanceAcrossMappingVersions is the traceability
// requirement end to end: two events, two mapping versions, both explainable.
func TestWorkerRecordsProvenanceAcrossMappingVersions(t *testing.T) {
	rawStore := raw.NewMemoryRawStore()
	normalizedStore := normalized.NewMemoryStore()
	quarantineStore := quarantine.NewMemoryStore()
	registryStore := registry.NewMemoryStore()

	const eventOne = `{"timestamp":"2026-08-28T18:30:12Z","firewall":{"action":"deny","protocol":"TCP"},` +
		`"network":{"source":{"ip":"192.168.1.20","port":54321}}}`

	// Event 1 establishes the source's base mapping.
	msgOne := jsonMsg("msg-1", "evt_prov_1", eventOne)
	bufOne := &mockWorkerBuffer{messages: []buffer.RawMessage{msgOne}}

	w1, err := setupTestWorkerWithStores(
		bufOne, rawStore, buffer.NewMemoryIdempotencyStore(), normalizedStore, quarantineStore,
		Config{DriftAnalyzer: buildRegistryEngine(registryStore)},
	)
	if err != nil {
		t.Fatalf("setup: %v", err)
	}

	ctxOne, cancelOne := context.WithTimeout(context.Background(), 400*time.Millisecond)
	defer cancelOne()
	_ = w1.Start(ctxOne)

	waitFor(t, time.Second, func() bool {
		count, _ := normalizedStore.Count(context.Background())
		return count == 1
	}, "the first event to be persisted")

	// Event 2 adds an optional field: minor drift, adapted to a new version.
	const eventTwo = `{"timestamp":"2026-08-28T18:30:12Z","device_uuid":"abc-123","firewall":{"action":"deny"}}`
	msgTwo := jsonMsg("msg-2", "evt_prov_2", eventTwo)
	bufTwo := &mockWorkerBuffer{messages: []buffer.RawMessage{msgTwo}}

	w2, err := setupTestWorkerWithStores(
		bufTwo, rawStore, buffer.NewMemoryIdempotencyStore(), normalizedStore, quarantineStore,
		Config{DriftAnalyzer: buildRegistryEngine(registryStore)},
	)
	if err != nil {
		t.Fatalf("setup w2: %v", err)
	}

	ctxTwo, cancelTwo := context.WithTimeout(context.Background(), 400*time.Millisecond)
	defer cancelTwo()
	_ = w2.Start(ctxTwo)

	waitFor(t, time.Second, func() bool {
		count, _ := normalizedStore.Count(context.Background())
		return count == 2
	}, "the second event to be persisted")

	// Both events are stored, each naming the exact version that processed it.
	first, err := normalizedStore.Get(context.Background(), "evt_prov_1")
	if err != nil {
		t.Fatalf("expected the first event: %v", err)
	}
	second, err := normalizedStore.Get(context.Background(), "evt_prov_2")
	if err != nil {
		t.Fatalf("expected the second event: %v", err)
	}

	if first.Provenance.MappingVersion != 1 {
		t.Errorf("expected the first event on mapping v1, got v%d", first.Provenance.MappingVersion)
	}
	if second.Provenance.MappingVersion != 2 {
		t.Errorf("expected the second event on mapping v2, got v%d", second.Provenance.MappingVersion)
	}
	if first.Provenance.ParserID != "generic_json" || second.Provenance.ParserID != "generic_json" {
		t.Errorf("expected the json parser on both events, got %q and %q",
			first.Provenance.ParserID, second.Provenance.ParserID)
	}
	if first.Provenance.ParserVersion == "" {
		t.Error("expected a parser version to be recorded")
	}
	if first.Provenance.SourceFingerprint == "" ||
		first.Provenance.SourceFingerprint != second.Provenance.SourceFingerprint {
		t.Error("expected both events to share one source fingerprint")
	}
	if first.Provenance.DriftStatus != string(models.DriftStatusStable) {
		t.Errorf("expected the first event to record stable drift, got %q", first.Provenance.DriftStatus)
	}
	if second.Provenance.DriftStatus != string(models.DriftStatusMinorDrift) {
		t.Errorf("expected the second event to record minor drift, got %q", second.Provenance.DriftStatus)
	}
	if first.Provenance.MappingID != second.Provenance.MappingID {
		t.Error("expected the mapping id to stay stable across versions")
	}

	// The raw object reference is unchanged and still points at the immutable copy.
	if first.RawObjectKey != raw.ObjectKey("evt_prov_1") {
		t.Errorf("unexpected raw object key %q", first.RawObjectKey)
	}

	// The stored payload is self-describing, so the event remains explainable
	// without a join.
	metadata := second.Event.Metadata
	if metadata.SourceFingerprint == "" || metadata.ParserID != "generic_json" {
		t.Errorf("expected the event metadata to carry provenance, got %+v", metadata)
	}
	if metadata.MappingVersion != 2 {
		t.Errorf("expected the event metadata to name mapping v2, got %d", metadata.MappingVersion)
	}

	// Both registry versions remain readable.
	for version := 1; version <= 2; version++ {
		if _, err := registryStore.GetVersion(context.Background(), registry.VersionRef{
			Fingerprint: first.Provenance.SourceFingerprint, MappingID: first.Provenance.MappingID, MappingVersion: version,
		}); err != nil {
			t.Errorf("expected mapping v%d to remain available: %v", version, err)
		}
	}
}

// TestWorkerBindsDeclaredAlias — the CSV parser reads exact column names, so a
// declared alias is applied by the binder after parsing.
func TestWorkerBindsDeclaredAlias(t *testing.T) {
	rawStore := raw.NewMemoryRawStore()
	normalizedStore := normalized.NewMemoryStore()
	quarantineStore := quarantine.NewMemoryStore()

	// "source_ip" is not a column the CSV parser looks for; the contract
	// declares it as an alias of src_ip.
	payload := "timestamp,action,protocol,source_ip,src_port,destination_ip,destination_port\n" +
		"2026-08-28T18:30:12Z,deny,TCP,192.168.1.20,54321,10.0.0.15,443\n"

	msg := buffer.RawMessage{
		ID: "msg-alias",
		Event: models.RawEvent{
			EventID:    "evt_alias",
			ReceivedAt: time.Now().UTC().Format(time.RFC3339),
			Format:     "csv",
			Source:     "firewall-csv",
			Payload:    payload,
		},
	}

	buf := &mockWorkerBuffer{messages: []buffer.RawMessage{msg}}
	w, err := setupTestWorkerWithStores(
		buf, rawStore, buffer.NewMemoryIdempotencyStore(), normalizedStore, quarantineStore,
		Config{DriftAnalyzer: buildRegistryEngine(registry.NewMemoryStore())},
	)
	if err != nil {
		t.Fatalf("setup: %v", err)
	}

	res, err := w.ProcessSingleEvent(context.Background(), msg.Event)
	if err != nil {
		t.Fatalf("expected the alias payload to process cleanly: %v", err)
	}

	event := res.UniversalEvent
	if event.Network == nil {
		t.Fatal("expected network info")
	}
	if event.Network.SrcIP != "192.168.1.20" {
		t.Errorf("expected the binder to fill SrcIP from source_ip, got %q", event.Network.SrcIP)
	}
	if event.Network.DstIP != "10.0.0.15" {
		t.Errorf("expected the binder to fill DstIP from destination_ip, got %q", event.Network.DstIP)
	}
	if event.Network.DstPort == nil || *event.Network.DstPort != 443 {
		t.Errorf("expected the binder to fill DstPort from destination_port, got %v", event.Network.DstPort)
	}
	if len(res.Bindings) == 0 {
		t.Error("expected the bindings to be reported on the result")
	}
	if res.SchemaDrift == nil || res.SchemaDrift.Entry == nil {
		t.Fatal("expected a mapping to be resolved")
	}
	if res.SchemaDrift.Entry.ParserID != "generic_csv" {
		t.Errorf("expected the csv parser, got %q", res.SchemaDrift.Entry.ParserID)
	}
}

// TestWorkerQuarantineCarriesProvenance — an event rejected for a major drift
// can be traced back to the source and mapping that rejected it.
func TestWorkerQuarantineCarriesProvenance(t *testing.T) {
	rawStore := raw.NewMemoryRawStore()
	normalizedStore := normalized.NewMemoryStore()
	quarantineStore := quarantine.NewMemoryStore()

	// A JSON array is not a JSON object: the payload cannot be parsed, so the
	// event is quarantined with its provenance attached.
	msg := jsonMsg("msg-q", "evt_q_prov", `[1,2,3]`)
	buf := &mockWorkerBuffer{messages: []buffer.RawMessage{msg}}

	w, err := setupTestWorkerWithStores(
		buf, rawStore, buffer.NewMemoryIdempotencyStore(), normalizedStore, quarantineStore,
		Config{DriftAnalyzer: buildRegistryEngine(registry.NewMemoryStore())},
	)
	if err != nil {
		t.Fatalf("setup: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 400*time.Millisecond)
	defer cancel()
	_ = w.Start(ctx)

	waitFor(t, time.Second, func() bool {
		count, _ := quarantineStore.Count(context.Background())
		return count == 1
	}, "the event to be quarantined")

	entry, err := quarantineStore.Get(context.Background(), "evt_q_prov")
	if err != nil {
		t.Fatalf("expected a quarantine entry: %v", err)
	}
	if entry.Provenance.SourceFingerprint == "" {
		t.Error("expected the quarantine entry to record the source fingerprint")
	}
	if entry.Provenance.ParserID != "generic_json" {
		t.Errorf("expected the json parser, got %q", entry.Provenance.ParserID)
	}
	if entry.Provenance.MappingID == "" {
		t.Error("expected the quarantine entry to record the mapping id")
	}
	if entry.Provenance.DriftStatus == "" {
		t.Error("expected the quarantine entry to record the drift status")
	}
}
