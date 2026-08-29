package parsing_test

import (
	"context"
	"strings"
	"testing"

	"github.com/Krishiv-Mahajan/LogMorph/internal/detection"
	"github.com/Krishiv-Mahajan/LogMorph/internal/models"
	"github.com/Krishiv-Mahajan/LogMorph/internal/parsing"
	"github.com/Krishiv-Mahajan/LogMorph/internal/parsing/parsers"
)

// setupIsolatedModulePipeline creates an in-memory instance of Krishiv's assigned module:
// Detector -> DriftDetector -> Parser Engine (backed by Parser Registry)
func setupIsolatedModulePipeline() (detection.Detector, detection.DriftDetector, parsing.Engine) {
	detector := detection.NewDetector()
	driftDetector := detection.NewDriftDetector()

	registry := parsing.NewRegistry()
	registry.Register(parsers.NewSyslogParser())
	registry.Register(parsers.NewJSONParser())
	registry.Register(parsers.NewCSVParser())

	engine := parsing.NewEngine(registry)
	return detector, driftDetector, engine
}

// STEP 3: Syslog Acceptance Test (no format hint)
func TestIsolatedPipeline_Syslog(t *testing.T) {
	detector, driftDetector, engine := setupIsolatedModulePipeline()
	ctx := context.Background()

	rawEvent := models.RawEvent{
		Payload: "Aug 28 18:30:12 firewall01 DENY TCP SRC=192.168.1.20:54321 DST=10.0.0.15:443",
	}

	// 1. Detection
	detectRes := detector.Detect(rawEvent.Payload, rawEvent.Format)
	if detectRes.Format != detection.FormatSyslog {
		t.Fatalf("expected detected format 'syslog', got %q", detectRes.Format)
	}
	if detectRes.SourceType != "firewall" {
		t.Errorf("expected source_type 'firewall', got %q", detectRes.SourceType)
	}
	if detectRes.Confidence < 0.5 {
		t.Errorf("expected confidence >= 0.5, got %f", detectRes.Confidence)
	}

	// 2. Drift Analysis
	driftRes, err := driftDetector.Analyze(ctx, rawEvent, detectRes)
	if err != nil {
		t.Fatalf("drift analysis error: %v", err)
	}
	if driftRes.Status != models.DriftStatusStable {
		t.Fatalf("expected drift status 'stable', got %q", driftRes.Status)
	}
	if driftRes.SuggestedAction != "route_to_parser" {
		t.Errorf("expected suggested_action 'route_to_parser', got %q", driftRes.SuggestedAction)
	}

	// 3. Parser Engine
	parsed, err := engine.Parse(ctx, rawEvent, detectRes)
	if err != nil {
		t.Fatalf("parser engine failed: %v", err)
	}

	// Assert exact ParsedEvent fields
	if parsed.Source.Identifier != "firewall01" {
		t.Errorf("expected source.identifier 'firewall01', got %q", parsed.Source.Identifier)
	}
	if parsed.Event.Action != "deny" {
		t.Errorf("expected event.action 'deny', got %q", parsed.Event.Action)
	}
	if parsed.Network == nil {
		t.Fatal("expected non-nil Network info")
	}
	if parsed.Network.Protocol != "TCP" {
		t.Errorf("expected network.protocol 'TCP', got %q", parsed.Network.Protocol)
	}
	if parsed.Network.SrcIP != "192.168.1.20" {
		t.Errorf("expected network.src_ip '192.168.1.20', got %q", parsed.Network.SrcIP)
	}
	if parsed.Network.SrcPort == nil || *parsed.Network.SrcPort != 54321 {
		t.Errorf("expected network.src_port 54321, got %v", parsed.Network.SrcPort)
	}
	if parsed.Network.DstIP != "10.0.0.15" {
		t.Errorf("expected network.dst_ip '10.0.0.15', got %q", parsed.Network.DstIP)
	}
	if parsed.Network.DstPort == nil || *parsed.Network.DstPort != 443 {
		t.Errorf("expected network.dst_port 443, got %v", parsed.Network.DstPort)
	}
}

// STEP 4: Flat JSON Acceptance Test (no format hint)
func TestIsolatedPipeline_JSON(t *testing.T) {
	detector, driftDetector, engine := setupIsolatedModulePipeline()
	ctx := context.Background()

	rawEvent := models.RawEvent{
		Payload: `{
			"timestamp": "2026-08-29T10:15:00Z",
			"action": "block",
			"src_ip": "192.168.1.50",
			"src_port": 45678,
			"dst_ip": "10.0.0.20",
			"dst_port": 443,
			"protocol": "TCP"
		}`,
	}

	// 1. Detection
	detectRes := detector.Detect(rawEvent.Payload, rawEvent.Format)
	if detectRes.Format != detection.FormatJSON {
		t.Fatalf("expected detected format 'json', got %q", detectRes.Format)
	}
	if detectRes.SourceType != "firewall" {
		t.Errorf("expected source_type 'firewall', got %q", detectRes.SourceType)
	}
	if detectRes.Confidence < 0.5 {
		t.Errorf("expected confidence >= 0.5, got %f", detectRes.Confidence)
	}

	// 2. Drift Analysis
	driftRes, err := driftDetector.Analyze(ctx, rawEvent, detectRes)
	if err != nil {
		t.Fatalf("drift analysis error: %v", err)
	}
	if driftRes.Status != models.DriftStatusStable {
		t.Fatalf("expected drift status 'stable', got %q", driftRes.Status)
	}

	// 3. Parser Engine
	parsed, err := engine.Parse(ctx, rawEvent, detectRes)
	if err != nil {
		t.Fatalf("parser engine failed: %v", err)
	}

	// Assert exact ParsedEvent fields
	if parsed.Timestamp != "2026-08-29T10:15:00Z" {
		t.Errorf("expected timestamp '2026-08-29T10:15:00Z', got %q", parsed.Timestamp)
	}
	if parsed.Event.Action != "block" {
		t.Errorf("expected event.action 'block', got %q", parsed.Event.Action)
	}
	if parsed.Network == nil {
		t.Fatal("expected non-nil Network info")
	}
	if parsed.Network.Protocol != "TCP" {
		t.Errorf("expected network.protocol 'TCP', got %q", parsed.Network.Protocol)
	}
	if parsed.Network.SrcIP != "192.168.1.50" {
		t.Errorf("expected network.src_ip '192.168.1.50', got %q", parsed.Network.SrcIP)
	}
	if parsed.Network.SrcPort == nil || *parsed.Network.SrcPort != 45678 {
		t.Errorf("expected network.src_port 45678, got %v", parsed.Network.SrcPort)
	}
	if parsed.Network.DstIP != "10.0.0.20" {
		t.Errorf("expected network.dst_ip '10.0.0.20', got %q", parsed.Network.DstIP)
	}
	if parsed.Network.DstPort == nil || *parsed.Network.DstPort != 443 {
		t.Errorf("expected network.dst_port 443, got %v", parsed.Network.DstPort)
	}
}

// STEP 5: CSV Acceptance Test (no format hint)
func TestIsolatedPipeline_CSV(t *testing.T) {
	detector, driftDetector, engine := setupIsolatedModulePipeline()
	ctx := context.Background()

	rawEvent := models.RawEvent{
		Payload: "timestamp,action,protocol,src_ip,src_port,dst_ip,dst_port\n2026-08-28T18:30:12Z,deny,TCP,192.168.1.20,54321,10.0.0.15,443",
	}

	// 1. Detection
	detectRes := detector.Detect(rawEvent.Payload, rawEvent.Format)
	if detectRes.Format != detection.FormatCSV {
		t.Fatalf("expected detected format 'csv', got %q", detectRes.Format)
	}
	if detectRes.SourceType != "firewall" {
		t.Errorf("expected source_type 'firewall', got %q", detectRes.SourceType)
	}
	if detectRes.Confidence < 0.5 {
		t.Errorf("expected confidence >= 0.5, got %f", detectRes.Confidence)
	}

	// 2. Drift Analysis
	driftRes, err := driftDetector.Analyze(ctx, rawEvent, detectRes)
	if err != nil {
		t.Fatalf("drift analysis error: %v", err)
	}
	if driftRes.Status != models.DriftStatusStable {
		t.Fatalf("expected drift status 'stable', got %q", driftRes.Status)
	}

	// 3. Parser Engine
	parsed, err := engine.Parse(ctx, rawEvent, detectRes)
	if err != nil {
		t.Fatalf("parser engine failed: %v", err)
	}

	// Assert exact ParsedEvent fields
	if parsed.Timestamp != "2026-08-28T18:30:12Z" {
		t.Errorf("expected timestamp '2026-08-28T18:30:12Z', got %q", parsed.Timestamp)
	}
	if parsed.Event.Action != "deny" {
		t.Errorf("expected event.action 'deny', got %q", parsed.Event.Action)
	}
	if parsed.Network == nil {
		t.Fatal("expected non-nil Network info")
	}
	if parsed.Network.Protocol != "TCP" {
		t.Errorf("expected network.protocol 'TCP', got %q", parsed.Network.Protocol)
	}
	if parsed.Network.SrcIP != "192.168.1.20" {
		t.Errorf("expected network.src_ip '192.168.1.20', got %q", parsed.Network.SrcIP)
	}
	if parsed.Network.SrcPort == nil || *parsed.Network.SrcPort != 54321 {
		t.Errorf("expected network.src_port 54321, got %v", parsed.Network.SrcPort)
	}
	if parsed.Network.DstIP != "10.0.0.15" {
		t.Errorf("expected network.dst_ip '10.0.0.15', got %q", parsed.Network.DstIP)
	}
	if parsed.Network.DstPort == nil || *parsed.Network.DstPort != 443 {
		t.Errorf("expected network.dst_port 443, got %v", parsed.Network.DstPort)
	}
}

// STEP 6: Explicit Format Hint Acceptance Test
func TestIsolatedPipeline_ExplicitFormatHint(t *testing.T) {
	detector, driftDetector, engine := setupIsolatedModulePipeline()
	ctx := context.Background()

	rawEvent := models.RawEvent{
		Format:  "json", // Explicit hint supplied
		Payload: `{"timestamp":"2026-08-28T18:30:12Z","action":"deny","src_ip":"10.0.0.1","src_port":1234,"dst_ip":"10.0.0.2","dst_port":80,"protocol":"TCP"}`,
	}

	// 1. Detection respects trusted hint
	detectRes := detector.Detect(rawEvent.Payload, rawEvent.Format)
	if detectRes.Format != "json" {
		t.Fatalf("expected format 'json', got %q", detectRes.Format)
	}
	if detectRes.Confidence != 1.0 {
		t.Errorf("expected confidence 1.0 for explicit hint, got %f", detectRes.Confidence)
	}

	// 2. Drift
	driftRes, err := driftDetector.Analyze(ctx, rawEvent, detectRes)
	if err != nil {
		t.Fatalf("drift analysis error: %v", err)
	}
	if driftRes.Status != models.DriftStatusStable {
		t.Fatalf("expected drift status 'stable', got %q", driftRes.Status)
	}

	// 3. Parser Engine
	parsed, err := engine.Parse(ctx, rawEvent, detectRes)
	if err != nil {
		t.Fatalf("parser engine failed: %v", err)
	}
	if parsed.Event.Action != "deny" {
		t.Errorf("expected action 'deny', got %q", parsed.Event.Action)
	}
	if parsed.Network.SrcIP != "10.0.0.1" {
		t.Errorf("expected src_ip '10.0.0.1', got %q", parsed.Network.SrcIP)
	}
}

// STEP 7: Unknown Format Acceptance Test
func TestIsolatedPipeline_UnknownFormat(t *testing.T) {
	detector, driftDetector, engine := setupIsolatedModulePipeline()
	ctx := context.Background()

	rawEvent := models.RawEvent{
		Payload: "Some unstructured plain text system log message without recognizable format",
	}

	// 1. Detection
	detectRes := detector.Detect(rawEvent.Payload, rawEvent.Format)
	if detectRes.Format != detection.FormatUnknown {
		t.Fatalf("expected format 'unknown', got %q", detectRes.Format)
	}
	if detectRes.Confidence != 0.0 {
		t.Errorf("expected confidence 0.0, got %f", detectRes.Confidence)
	}

	// 2. Drift Analysis
	driftRes, err := driftDetector.Analyze(ctx, rawEvent, detectRes)
	if err != nil {
		t.Fatalf("drift analysis error: %v", err)
	}
	if driftRes.Status != models.DriftStatusUnknown {
		t.Fatalf("expected drift status 'unknown', got %q", driftRes.Status)
	}
	if driftRes.SuggestedAction != "escalate_to_ai" {
		t.Errorf("expected suggested action 'escalate_to_ai', got %q", driftRes.SuggestedAction)
	}

	// 3. Parser Engine returns controlled error
	parsed, err := engine.Parse(ctx, rawEvent, detectRes)
	if err == nil {
		t.Fatal("expected error from engine on unknown format, got nil")
	}
	if parsed != nil {
		t.Fatalf("expected nil ParsedEvent on error, got: %+v", parsed)
	}
	if !strings.Contains(err.Error(), "parser selection failed") {
		t.Errorf("expected 'parser selection failed' error, got: %v", err)
	}
}

// STEP 8: Malformed Input Acceptance Test
func TestIsolatedPipeline_MalformedInput(t *testing.T) {
	detector, driftDetector, engine := setupIsolatedModulePipeline()
	ctx := context.Background()

	rawEvent := models.RawEvent{
		Format:  "json", // Explicit hint for JSON, but invalid payload syntax
		Payload: `{"action": "deny", "src_ip":`,
	}

	// 1. Detection
	detectRes := detector.Detect(rawEvent.Payload, rawEvent.Format)
	if detectRes.Format != "json" {
		t.Fatalf("expected format 'json', got %q", detectRes.Format)
	}

	// 2. Drift Analysis
	driftRes, err := driftDetector.Analyze(ctx, rawEvent, detectRes)
	if err != nil {
		t.Fatalf("drift analysis error: %v", err)
	}
	if driftRes.Status != models.DriftStatusStable {
		t.Fatalf("expected drift status 'stable', got %q", driftRes.Status)
	}

	// 3. Parser Engine returns controlled error from JSON parser
	parsed, err := engine.Parse(ctx, rawEvent, detectRes)
	if err == nil {
		t.Fatal("expected parsing error on malformed JSON, got nil")
	}
	if parsed != nil {
		t.Fatalf("expected nil ParsedEvent on error, got: %+v", parsed)
	}
	if !strings.Contains(err.Error(), "parsing failed for format json") {
		t.Errorf("expected 'parsing failed for format json' error, got: %v", err)
	}
}
