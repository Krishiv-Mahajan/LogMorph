package drift

import (
	"context"
	"testing"

	"github.com/Krishiv-Mahajan/LogMorph/internal/models"
	"github.com/Krishiv-Mahajan/LogMorph/internal/parsing"
	"github.com/Krishiv-Mahajan/LogMorph/internal/parsing/parsers"
	"github.com/Krishiv-Mahajan/LogMorph/internal/registry"
)

// realCatalog wires the engine to the descriptors the production parsers
// actually declare, so these tests validate the shipped contracts rather than a
// fixture that could drift away from them.
func realCatalog() *parsing.Registry {
	parserRegistry := parsing.NewRegistry()
	parserRegistry.Register(parsers.NewJSONParser())
	parserRegistry.Register(parsers.NewCSVParser())
	parserRegistry.Register(parsers.NewSyslogParser())
	return parserRegistry
}

// harness bundles a drift engine with its store for assertions.
type harness struct {
	engine *Engine
	store  *registry.MemoryStore
	ctx    context.Context
}

func newHarness() *harness {
	store := registry.NewMemoryStore()
	return &harness{engine: NewEngine(store, realCatalog()), store: store, ctx: context.Background()}
}

// analyze runs drift analysis for a payload from a fixed source.
func (h *harness) analyze(t *testing.T, format, source, payload string) *Result {
	t.Helper()

	raw := models.RawEvent{
		EventID: "evt-" + format,
		Format:  format,
		Source:  source,
		Payload: payload,
	}
	detection := models.DetectionResult{Format: format, SourceType: "firewall", Confidence: 1.0}

	result, err := h.engine.Analyze(h.ctx, raw, detection)
	if err != nil {
		t.Fatalf("drift analysis failed: %v", err)
	}
	return result
}

const validJSON = `{"timestamp":"2026-08-28T18:30:12Z","firewall":{"action":"deny","protocol":"TCP"},` +
	`"network":{"source":{"ip":"192.168.1.20","port":54321},"destination":{"ip":"10.0.0.15","port":443}}}`

// ── 1. Known stable source ───────────────────────────────────────────────────

func TestEngineStableSourceSelectsExistingMapping(t *testing.T) {
	h := newHarness()

	first := h.analyze(t, "json", "firewall-01", validJSON)
	if first.Classification != models.DriftStatusStable {
		t.Fatalf("expected the first sight of a source to be stable, got %q (%s)", first.Classification, first.Reason)
	}
	if first.Entry == nil {
		t.Fatal("expected a mapping entry")
	}
	if first.Entry.MappingVersion != 1 {
		t.Errorf("expected the base mapping to be version 1, got %d", first.Entry.MappingVersion)
	}
	if first.Entry.ParserID != "generic_json" {
		t.Errorf("expected the json parser, got %q", first.Entry.ParserID)
	}
	if first.EscalationRequired {
		t.Error("a stable event must not require escalation")
	}

	// A second identical event reuses the same mapping — no new version.
	second := h.analyze(t, "json", "firewall-01", validJSON)
	if second.Classification != models.DriftStatusStable {
		t.Errorf("expected the second event to be stable, got %q (%s)", second.Classification, second.Reason)
	}
	if second.Entry.MappingVersion != 1 {
		t.Errorf("expected the same mapping version, got %d", second.Entry.MappingVersion)
	}
	if second.Adapted {
		t.Error("expected no adaptation for an unchanged payload")
	}

	versions, err := h.store.VersionsFor(h.ctx, first.Fingerprint)
	if err != nil {
		t.Fatalf("failed to list versions: %v", err)
	}
	if len(versions) != 1 {
		t.Errorf("expected exactly 1 mapping version, got %d", len(versions))
	}
}

// ── 2. Minor drift: additive optional field ──────────────────────────────────

func TestEngineMinorDriftAdaptsAdditiveField(t *testing.T) {
	h := newHarness()

	base := h.analyze(t, "json", "firewall-01", validJSON)
	if base.Entry.MappingVersion != 1 {
		t.Fatalf("expected the base mapping at version 1, got %d", base.Entry.MappingVersion)
	}

	// The source starts sending an extra scalar field.
	drifted := h.analyze(t, "json", "firewall-01",
		`{"timestamp":"2026-08-28T18:30:12Z","device_uuid":"abc-123","firewall":{"action":"deny"}}`)

	if drifted.Classification != models.DriftStatusMinorDrift {
		t.Fatalf("expected minor drift, got %q (%s)", drifted.Classification, drifted.Reason)
	}
	if !drifted.Adapted {
		t.Fatal("expected a safe additive field to be adapted")
	}
	if drifted.EscalationRequired {
		t.Error("a safe adaptation must not require escalation")
	}
	if drifted.Entry.MappingVersion != 2 {
		t.Errorf("expected mapping version 2, got %d", drifted.Entry.MappingVersion)
	}
	if drifted.Entry.ParentVersion != 1 {
		t.Errorf("expected the new version to record its parent, got %d", drifted.Entry.ParentVersion)
	}
	if drifted.Entry.MappingID != base.Entry.MappingID {
		t.Error("expected the mapping id to stay stable across versions")
	}

	// The added field is recorded as optional and unbound: it is versioned, but
	// no meaning was invented for it.
	stored, err := h.store.GetVersion(h.ctx, registry.VersionRef{
		Fingerprint: drifted.Fingerprint, MappingID: "generic_json_mapping", MappingVersion: 2,
	})
	if err != nil {
		t.Fatalf("failed to read v2: %v", err)
	}
	field, ok := stored.Contract.Lookup("device_uuid")
	if !ok {
		t.Fatal("expected the adapted contract to declare device_uuid")
	}
	if !field.Optional {
		t.Error("expected an adapted field to be optional")
	}
	if field.Target != "" {
		t.Errorf("expected an adapted field to have no invented target, got %q", field.Target)
	}

	// The change is reported with enough detail to investigate.
	if len(drifted.Changes) != 1 || drifted.Changes[0].Kind != ChangeFieldAdded || !drifted.Changes[0].Safe {
		t.Errorf("unexpected change set: %+v", drifted.Changes)
	}
}

// ── 3. Previous version remains available ────────────────────────────────────

func TestEnginePreviousVersionRemainsAvailable(t *testing.T) {
	h := newHarness()

	v1 := h.analyze(t, "json", "firewall-01", validJSON)
	originalHash := v1.Entry.Contract.Hash()

	h.analyze(t, "json", "firewall-01", `{"timestamp":"2026-08-28T18:30:12Z","device_uuid":"abc-123"}`)

	old, err := h.store.GetVersion(h.ctx, registry.VersionRef{
		Fingerprint: v1.Fingerprint, MappingID: "generic_json_mapping", MappingVersion: 1,
	})
	if err != nil {
		t.Fatalf("expected the previous mapping version to remain available: %v", err)
	}
	if old.Contract.Hash() != originalHash {
		t.Error("the previous version's contract was modified")
	}
	if old.Status != registry.StatusSuperseded {
		t.Errorf("expected the previous version to be superseded, got %q", old.Status)
	}
	if _, ok := old.Contract.Lookup("device_uuid"); ok {
		t.Error("expected v1 not to contain the later addition")
	}
}

// ── 4. Incompatible type change ──────────────────────────────────────────────

func TestEngineIncompatibleTypeIsNotAdapted(t *testing.T) {
	h := newHarness()
	h.analyze(t, "json", "firewall-01", validJSON)

	tests := []struct {
		name    string
		payload string
	}{
		{
			name:    "numeric field becomes non-numeric",
			payload: `{"timestamp":"2026-08-28T18:30:12Z","src_port":"not-a-port"}`,
		},
		{
			name:    "scalar field becomes a nested object",
			payload: `{"timestamp":"2026-08-28T18:30:12Z","src_port":{"value":443}}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := h.analyze(t, "json", "firewall-01", tt.payload)

			if result.Classification != models.DriftStatusMajorDrift {
				t.Fatalf("expected major drift, got %q (%s)", result.Classification, result.Reason)
			}
			if !result.EscalationRequired {
				t.Error("expected an unsafe change to require escalation")
			}
			if result.Adapted {
				t.Error("an unsafe change must never be adapted")
			}
			if result.Entry.MappingVersion != 1 {
				t.Errorf("expected the active mapping to stay at v1, got %d", result.Entry.MappingVersion)
			}
			if len(result.Changes) == 0 {
				t.Fatal("expected the change to be reported")
			}
			for _, change := range result.Changes {
				if change.Safe {
					t.Errorf("expected every reported change to be unsafe, got %+v", change)
				}
			}
		})
	}
}

// ── 5. Required field disappears ─────────────────────────────────────────────

func TestEngineMissingRequiredFieldIsNotAdapted(t *testing.T) {
	h := newHarness()
	h.analyze(t, "json", "firewall-01", validJSON)

	result := h.analyze(t, "json", "firewall-01", `{"firewall":{"action":"deny"}}`)

	if result.Classification != models.DriftStatusMajorDrift {
		t.Fatalf("expected major drift, got %q (%s)", result.Classification, result.Reason)
	}
	if !result.EscalationRequired || result.Adapted {
		t.Error("a disappearing required field must be escalated, never adapted")
	}

	found := false
	for _, change := range result.Changes {
		if change.Kind == ChangeRequiredMissing && change.Field == "timestamp" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected a required_field_missing change for timestamp, got %+v", result.Changes)
	}
}

// ── 6. Ambiguous mapping ─────────────────────────────────────────────────────

// TestEngineAmbiguousMappingIsNotAdapted — the same target reached through two
// names with different values has no deterministic answer.
func TestEngineAmbiguousMappingIsNotAdapted(t *testing.T) {
	h := newHarness()
	h.analyze(t, "json", "firewall-01", validJSON)

	result := h.analyze(t, "json", "firewall-01",
		`{"timestamp":"2026-08-28T18:30:12Z","src_ip":"10.0.0.1","source_ip":"10.0.0.2"}`)

	if result.Classification != models.DriftStatusMajorDrift {
		t.Fatalf("expected major drift, got %q (%s)", result.Classification, result.Reason)
	}
	if result.Adapted || !result.EscalationRequired {
		t.Error("an ambiguous mapping must be escalated, never adapted")
	}

	found := false
	for _, change := range result.Changes {
		if change.Kind == ChangeAmbiguous {
			found = true
		}
	}
	if !found {
		t.Errorf("expected an ambiguous_mapping change, got %+v", result.Changes)
	}
}

// TestEngineAgreeingAliasIsNotAmbiguous — the same value through two names is
// not a conflict, and a declared alias is vocabulary the contract already
// covers, so it is not drift at all.
func TestEngineAgreeingAliasIsNotAmbiguous(t *testing.T) {
	h := newHarness()

	result := h.analyze(t, "json", "firewall-01",
		`{"timestamp":"2026-08-28T18:30:12Z","src_ip":"10.0.0.1","source_ip":"10.0.0.1"}`)

	if result.Classification != models.DriftStatusStable {
		t.Errorf("expected a declared alias carrying the same value to be stable, got %q (%s)",
			result.Classification, result.Reason)
	}
	if result.Adapted {
		t.Error("expected no adaptation when the contract already covers the names used")
	}
}

// ── 7. After adaptation the newest mapping is selected ───────────────────────

func TestEngineNewestMappingSelectedAfterAdaptation(t *testing.T) {
	h := newHarness()
	h.analyze(t, "json", "firewall-01", validJSON)

	added := `{"timestamp":"2026-08-28T18:30:12Z","device_uuid":"abc-123"}`
	if adapted := h.analyze(t, "json", "firewall-01", added); adapted.Entry.MappingVersion != 2 {
		t.Fatalf("expected the adaptation to produce v2, got %d", adapted.Entry.MappingVersion)
	}

	// The same payload again is now stable against v2 and creates nothing new.
	repeat := h.analyze(t, "json", "firewall-01", added)
	if repeat.Classification != models.DriftStatusStable {
		t.Errorf("expected the adapted contract to make the source stable, got %q (%s)",
			repeat.Classification, repeat.Reason)
	}
	if repeat.Entry.MappingVersion != 2 {
		t.Errorf("expected v2 to be selected, got %d", repeat.Entry.MappingVersion)
	}

	versions, err := h.store.VersionsFor(h.ctx, repeat.Fingerprint)
	if err != nil {
		t.Fatalf("failed to list versions: %v", err)
	}
	if len(versions) != 2 {
		t.Errorf("expected exactly 2 versions after one adaptation, got %d", len(versions))
	}
}

// ── 8. Both mapping versions remain traceable ────────────────────────────────

func TestEngineBothVersionsRemainTraceable(t *testing.T) {
	h := newHarness()

	before := h.analyze(t, "json", "firewall-01", validJSON)
	after := h.analyze(t, "json", "firewall-01", `{"timestamp":"2026-08-28T18:30:12Z","device_uuid":"abc"}`)

	if before.Entry.MappingVersion == after.Entry.MappingVersion {
		t.Fatal("expected the two events to be processed under different mapping versions")
	}

	// Each result names the exact version that processed it, and both versions
	// are still readable from the registry.
	for _, result := range []*Result{before, after} {
		entry, err := h.store.GetVersion(h.ctx, result.Entry.Ref())
		if err != nil {
			t.Fatalf("expected version %d to remain readable: %v", result.Entry.MappingVersion, err)
		}
		if entry.Fingerprint != before.Fingerprint {
			t.Error("expected both events to share one source fingerprint")
		}
		if entry.Contract.Hash() != result.Entry.Contract.Hash() {
			t.Error("expected the stored contract to match the one reported for the event")
		}
	}
}

// ── CSV and syslog contracts ─────────────────────────────────────────────────

func TestEngineCSVAdditiveColumn(t *testing.T) {
	h := newHarness()

	const base = "timestamp,action,protocol,src_ip,src_port,dst_ip,dst_port\n" +
		"2026-08-28T18:30:12Z,deny,TCP,192.168.1.20,54321,10.0.0.15,443\n"

	first := h.analyze(t, "csv", "firewall-csv", base)
	if first.Classification != models.DriftStatusStable {
		t.Fatalf("expected the base CSV to be stable, got %q (%s)", first.Classification, first.Reason)
	}
	if first.Entry.ParserID != "generic_csv" {
		t.Errorf("expected the csv parser, got %q", first.Entry.ParserID)
	}

	// A new column arrives.
	const withColumn = "timestamp,action,protocol,src_ip,src_port,dst_ip,dst_port,rule_id\n" +
		"2026-08-28T18:30:12Z,deny,TCP,192.168.1.20,54321,10.0.0.15,443,R-42\n"

	drifted := h.analyze(t, "csv", "firewall-csv", withColumn)
	if drifted.Classification != models.DriftStatusMinorDrift || !drifted.Adapted {
		t.Fatalf("expected a new column to be adapted, got %q adapted=%t (%s)",
			drifted.Classification, drifted.Adapted, drifted.Reason)
	}
	if drifted.Entry.MappingVersion != 2 {
		t.Errorf("expected v2, got %d", drifted.Entry.MappingVersion)
	}
}

// TestEngineCSVPortedColumnStopsParsing — a column declared as an integer that
// starts carrying text is a change in meaning, so it is escalated.
func TestEngineCSVPortedColumnStopsParsing(t *testing.T) {
	h := newHarness()

	const base = "timestamp,action,src_port\n2026-08-28T18:30:12Z,deny,54321\n"
	h.analyze(t, "csv", "firewall-csv", base)

	const broken = "timestamp,action,src_port\n2026-08-28T18:30:12Z,deny,\"tcp/443\"\n"
	result := h.analyze(t, "csv", "firewall-csv", broken)

	if result.Classification != models.DriftStatusMajorDrift || result.Adapted {
		t.Fatalf("expected an incompatible type change to be escalated, got %q adapted=%t",
			result.Classification, result.Adapted)
	}
}

func TestEngineSyslogAdditiveKeyValue(t *testing.T) {
	h := newHarness()

	const base = "Aug 28 18:30:12 firewall01 DENY TCP SRC=192.168.1.20:54321 DST=10.0.0.15:443"
	first := h.analyze(t, "syslog", "firewall-syslog", base)
	if first.Classification != models.DriftStatusStable {
		t.Fatalf("expected the base syslog line to be stable, got %q (%s)", first.Classification, first.Reason)
	}
	if first.Entry.ParserID != "generic_syslog" {
		t.Errorf("expected the syslog parser, got %q", first.Entry.ParserID)
	}

	// A new key=value pair appears.
	const drifted = "Aug 28 18:30:12 firewall01 DENY TCP SRC=192.168.1.20:54321 DST=10.0.0.15:443 RULE=1001"
	result := h.analyze(t, "syslog", "firewall-syslog", drifted)

	if result.Classification != models.DriftStatusMinorDrift || !result.Adapted {
		t.Fatalf("expected an added KV pair to be adapted, got %q adapted=%t (%s)",
			result.Classification, result.Adapted, result.Reason)
	}
}

// TestEngineSyslogMissingOptionalKeyIsNotDrift — a syslog line may legitimately
// carry no key=value pairs, and nothing is declared required.
func TestEngineSyslogMissingOptionalKeyIsNotDrift(t *testing.T) {
	h := newHarness()

	h.analyze(t, "syslog", "firewall-syslog", "Aug 28 18:30:12 firewall01 DENY TCP SRC=192.168.1.20 DST=10.0.0.15")
	result := h.analyze(t, "syslog", "firewall-syslog", "Aug 28 18:30:12 firewall01 DENY TCP")

	if result.Classification != models.DriftStatusStable {
		t.Errorf("expected an absent optional key not to be drift, got %q (%s)", result.Classification, result.Reason)
	}
}

// ── Sources stay independent, and unknown formats escalate ───────────────────

func TestEngineSourcesAreIndependent(t *testing.T) {
	h := newHarness()

	first := h.analyze(t, "json", "firewall-01", validJSON)
	second := h.analyze(t, "json", "firewall-02", validJSON)

	if first.Fingerprint == second.Fingerprint {
		t.Fatal("expected different sources to have different fingerprints")
	}
	if second.Entry.MappingVersion != 1 {
		t.Errorf("expected a second source to start its own chain at v1, got %d", second.Entry.MappingVersion)
	}
	if second.Classification != models.DriftStatusStable {
		t.Errorf("expected the second source to be stable, got %q", second.Classification)
	}

	// Drift on one source must not touch the other's chain.
	h.analyze(t, "json", "firewall-02", `{"timestamp":"2026-08-28T18:30:12Z","vendor_field":"x"}`)

	othersVersions, err := h.store.VersionsFor(h.ctx, second.Fingerprint)
	if err != nil {
		t.Fatalf("failed to list the second source's versions: %v", err)
	}
	if len(othersVersions) != 2 {
		t.Errorf("expected the second source to reach 2 versions, got %d", len(othersVersions))
	}

	firstVersions, err := h.store.VersionsFor(h.ctx, first.Fingerprint)
	if err != nil {
		t.Fatalf("failed to list the first source's versions: %v", err)
	}
	if len(firstVersions) != 1 {
		t.Errorf("expected the first source to be unaffected, got %d versions", len(firstVersions))
	}
}

func TestEngineUnknownFormatEscalates(t *testing.T) {
	h := newHarness()

	result := h.analyze(t, "xml", "app-server", "<log><action>deny</action></log>")

	if result.Classification != models.DriftStatusUnknown {
		t.Errorf("expected unknown drift for an unmapped format, got %q", result.Classification)
	}
	if !result.EscalationRequired {
		t.Error("expected an unmapped format to require escalation")
	}
	if result.Entry != nil {
		t.Error("expected no mapping to be selected for an unmapped format")
	}
}

// TestEngineMalformedPayloadIsUnknownNotStable — an unparseable payload must not
// be silently recorded as matching the contract.
func TestEngineMalformedPayloadIsUnknownNotStable(t *testing.T) {
	h := newHarness()
	h.analyze(t, "json", "firewall-01", validJSON)

	result := h.analyze(t, "json", "firewall-01", `{"broken": `)

	if result.Classification != models.DriftStatusUnknown {
		t.Errorf("expected unknown drift, got %q", result.Classification)
	}
	if result.Entry == nil {
		t.Error("expected the active mapping to still be reported for parsing")
	}
	if result.Entry.MappingVersion != 1 {
		t.Errorf("expected the active mapping to be untouched, got v%d", result.Entry.MappingVersion)
	}
}

func TestEngineAdaptationIsIdempotentAcrossWorkers(t *testing.T) {
	// Two engines over one store simulate two workers observing the same drift.
	store := registry.NewMemoryStore()
	catalog := realCatalog()
	engineA := NewEngine(store, catalog)
	engineB := NewEngine(store, catalog)

	raw := models.RawEvent{Format: "json", Source: "firewall-01", Payload: validJSON}
	detection := models.DetectionResult{Format: "json", SourceType: "firewall", Confidence: 1.0}
	if _, err := engineA.Analyze(context.Background(), raw, detection); err != nil {
		t.Fatalf("engine A bootstrap failed: %v", err)
	}

	drifted := models.RawEvent{
		Format:  "json",
		Source:  "firewall-01",
		Payload: `{"timestamp":"2026-08-28T18:30:12Z","device_uuid":"abc"}`,
	}
	first, err := engineA.Analyze(context.Background(), drifted, detection)
	if err != nil {
		t.Fatalf("engine A adaptation failed: %v", err)
	}
	second, err := engineB.Analyze(context.Background(), drifted, detection)
	if err != nil {
		t.Fatalf("engine B adaptation failed: %v", err)
	}

	// The second observation finds the field already declared and creates
	// nothing new.
	if second.Adapted {
		t.Error("expected the second worker to find the field already adapted")
	}
	if second.Entry.MappingVersion != first.Entry.MappingVersion {
		t.Errorf("expected both workers to agree on the version, got %d and %d",
			first.Entry.MappingVersion, second.Entry.MappingVersion)
	}

	versions, err := store.VersionsFor(context.Background(), first.Fingerprint)
	if err != nil {
		t.Fatalf("failed to list versions: %v", err)
	}
	if len(versions) != 2 {
		t.Errorf("expected exactly 2 versions (base + one adaptation), got %d", len(versions))
	}
}
