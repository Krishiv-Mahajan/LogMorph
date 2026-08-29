package parsing

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/Krishiv-Mahajan/LogMorph/internal/models"
	"github.com/Krishiv-Mahajan/LogMorph/internal/parsing/parsers"
)

// setupStandardEngine initializes an Engine with the standard Syslog, JSON, and CSV parsers.
func setupStandardEngine() *DefaultEngine {
	reg := NewRegistry()
	reg.Register(parsers.NewSyslogParser())
	reg.Register(parsers.NewJSONParser())
	reg.Register(parsers.NewCSVParser())
	return NewEngine(reg)
}

func TestEngine_SyslogDispatch(t *testing.T) {
	engine := setupStandardEngine()
	ctx := context.Background()

	raw := models.RawEvent{
		EventID:    "evt_syslog_01",
		ReceivedAt: time.Now().UTC().Format(time.RFC3339),
		Format:     "syslog",
		Source:     "firewall-01",
		Payload:    "Aug 28 18:30:12 firewall01 DENY TCP SRC=192.168.1.20:54321 DST=10.0.0.15:443",
	}

	detection := models.DetectionResult{
		Format:     "syslog",
		SourceType: "firewall",
		Confidence: 0.85,
	}

	parsed, err := engine.Parse(ctx, raw, detection)
	if err != nil {
		t.Fatalf("Engine.Parse failed on syslog: %v", err)
	}

	if parsed.Event.Action != "deny" {
		t.Errorf("expected action 'deny', got %q", parsed.Event.Action)
	}
	if parsed.Network == nil {
		t.Fatal("expected non-nil Network info")
	}
	if parsed.Network.Protocol != "TCP" {
		t.Errorf("expected protocol 'TCP', got %q", parsed.Network.Protocol)
	}
	if parsed.Network.SrcIP != "192.168.1.20" {
		t.Errorf("expected src_ip '192.168.1.20', got %q", parsed.Network.SrcIP)
	}
	if parsed.Network.SrcPort == nil || *parsed.Network.SrcPort != 54321 {
		t.Errorf("expected src_port 54321, got %v", parsed.Network.SrcPort)
	}
	if parsed.Network.DstIP != "10.0.0.15" {
		t.Errorf("expected dst_ip '10.0.0.15', got %q", parsed.Network.DstIP)
	}
	if parsed.Network.DstPort == nil || *parsed.Network.DstPort != 443 {
		t.Errorf("expected dst_port 443, got %v", parsed.Network.DstPort)
	}
	if parsed.Source.Identifier != "firewall-01" {
		t.Errorf("expected identifier 'firewall-01', got %q", parsed.Source.Identifier)
	}
}

func TestEngine_JSONDispatch(t *testing.T) {
	engine := setupStandardEngine()
	ctx := context.Background()

	raw := models.RawEvent{
		EventID:    "evt_json_01",
		ReceivedAt: time.Now().UTC().Format(time.RFC3339),
		Format:     "json",
		Source:     "firewall-02",
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

	detection := models.DetectionResult{
		Format:     "json",
		SourceType: "firewall",
		Confidence: 0.95,
	}

	parsed, err := engine.Parse(ctx, raw, detection)
	if err != nil {
		t.Fatalf("Engine.Parse failed on JSON: %v", err)
	}

	if parsed.Timestamp != "2026-08-29T10:15:00Z" {
		t.Errorf("expected timestamp '2026-08-29T10:15:00Z', got %q", parsed.Timestamp)
	}
	if parsed.Event.Action != "block" {
		t.Errorf("expected action 'block', got %q", parsed.Event.Action)
	}
	if parsed.Network == nil {
		t.Fatal("expected non-nil Network info")
	}
	if parsed.Network.Protocol != "TCP" {
		t.Errorf("expected protocol 'TCP', got %q", parsed.Network.Protocol)
	}
	if parsed.Network.SrcIP != "192.168.1.50" {
		t.Errorf("expected src_ip '192.168.1.50', got %q", parsed.Network.SrcIP)
	}
	if parsed.Network.SrcPort == nil || *parsed.Network.SrcPort != 45678 {
		t.Errorf("expected src_port 45678, got %v", parsed.Network.SrcPort)
	}
	if parsed.Network.DstIP != "10.0.0.20" {
		t.Errorf("expected dst_ip '10.0.0.20', got %q", parsed.Network.DstIP)
	}
	if parsed.Network.DstPort == nil || *parsed.Network.DstPort != 443 {
		t.Errorf("expected dst_port 443, got %v", parsed.Network.DstPort)
	}
}

func TestEngine_CSVDispatch(t *testing.T) {
	engine := setupStandardEngine()
	ctx := context.Background()

	raw := models.RawEvent{
		EventID:    "evt_csv_01",
		ReceivedAt: time.Now().UTC().Format(time.RFC3339),
		Format:     "csv",
		Source:     "firewall-03",
		Payload:    "timestamp,action,protocol,src_ip,src_port,dst_ip,dst_port\n2026-08-29T10:20:00Z,DENY,TCP,192.168.1.60,51234,10.0.0.30,443",
	}

	detection := models.DetectionResult{
		Format:     "csv",
		SourceType: "firewall",
		Confidence: 0.90,
	}

	parsed, err := engine.Parse(ctx, raw, detection)
	if err != nil {
		t.Fatalf("Engine.Parse failed on CSV: %v", err)
	}

	if parsed.Timestamp != "2026-08-29T10:20:00Z" {
		t.Errorf("expected timestamp '2026-08-29T10:20:00Z', got %q", parsed.Timestamp)
	}
	if parsed.Event.Action != "deny" {
		t.Errorf("expected action 'deny', got %q", parsed.Event.Action)
	}
	if parsed.Network == nil {
		t.Fatal("expected non-nil Network info")
	}
	if parsed.Network.Protocol != "TCP" {
		t.Errorf("expected protocol 'TCP', got %q", parsed.Network.Protocol)
	}
	if parsed.Network.SrcIP != "192.168.1.60" {
		t.Errorf("expected src_ip '192.168.1.60', got %q", parsed.Network.SrcIP)
	}
	if parsed.Network.SrcPort == nil || *parsed.Network.SrcPort != 51234 {
		t.Errorf("expected src_port 51234, got %v", parsed.Network.SrcPort)
	}
	if parsed.Network.DstIP != "10.0.0.30" {
		t.Errorf("expected dst_ip '10.0.0.30', got %q", parsed.Network.DstIP)
	}
	if parsed.Network.DstPort == nil || *parsed.Network.DstPort != 443 {
		t.Errorf("expected dst_port 443, got %v", parsed.Network.DstPort)
	}
}

func TestEngine_UnknownOrUnregisteredFormat(t *testing.T) {
	engine := setupStandardEngine()
	ctx := context.Background()

	raw := models.RawEvent{
		Payload: "<log><msg>test</msg></log>",
	}

	detection := models.DetectionResult{
		Format: "xml",
	}

	parsed, err := engine.Parse(ctx, raw, detection)
	if err == nil {
		t.Fatal("expected error for unregistered format 'xml', got nil")
	}
	if parsed != nil {
		t.Fatalf("expected nil ParsedEvent, got: %+v", parsed)
	}
	if !strings.Contains(err.Error(), "parser selection failed") {
		t.Errorf("expected 'parser selection failed' error, got: %v", err)
	}
}

func TestEngine_EmptyDetectionFormat(t *testing.T) {
	engine := setupStandardEngine()
	ctx := context.Background()

	// Provide raw JSON payload but empty detection format
	raw := models.RawEvent{
		Payload: `{"timestamp":"2026-08-29T10:15:00Z","action":"block"}`,
	}

	detection := models.DetectionResult{
		Format: "", // Empty detection format
	}

	parsed, err := engine.Parse(ctx, raw, detection)
	if err == nil {
		t.Fatal("expected error when detection format is empty, got nil")
	}
	if parsed != nil {
		t.Fatalf("expected nil ParsedEvent, got: %+v", parsed)
	}
	// Verify the engine did NOT perform silent auto-detection
	if !strings.Contains(err.Error(), "parser selection failed") {
		t.Errorf("expected parser selection failure, got: %v", err)
	}
}

// erroringParser is a mock parser that deliberately fails on Parse.
type erroringParser struct{}

func (e *erroringParser) Format() string {
	return "test-error"
}

func (e *erroringParser) Parse(ctx context.Context, raw models.RawEvent) (*models.ParsedEvent, error) {
	return nil, errors.New("underlying corruption in log line at offset 42")
}

func TestEngine_ParserErrorPropagation(t *testing.T) {
	reg := NewRegistry()
	reg.Register(&erroringParser{})
	engine := NewEngine(reg)
	ctx := context.Background()

	raw := models.RawEvent{
		Payload: "corrupted line",
	}

	detection := models.DetectionResult{
		Format: "test-error",
	}

	parsed, err := engine.Parse(ctx, raw, detection)
	if err == nil {
		t.Fatal("expected error from erroring parser, got nil")
	}
	if parsed != nil {
		t.Fatalf("expected nil ParsedEvent on failure, got: %+v", parsed)
	}

	// Verify the original parser error is wrapped and not swallowed
	if !strings.Contains(err.Error(), "underlying corruption in log line at offset 42") {
		t.Errorf("expected underlying parser error to be preserved, got: %v", err)
	}
}

// customTestParser demonstrates that the Engine operates on any arbitrary Parser implementation.
type customTestParser struct {
	fmt string
}

func (c *customTestParser) Format() string {
	return c.fmt
}

func (c *customTestParser) Parse(ctx context.Context, raw models.RawEvent) (*models.ParsedEvent, error) {
	return &models.ParsedEvent{
		Timestamp: "2026-08-29T12:00:00Z",
		Source: models.SourceInfo{
			Identifier: "custom-sensor-01",
		},
		Event: models.EventInfo{
			Action: "custom-action",
		},
	}, nil
}

func TestEngine_RegistrySeparation(t *testing.T) {
	// Verify the Engine dynamically resolves custom parsers through the Registry interface
	reg := NewRegistry()
	reg.Register(&customTestParser{fmt: "custom-proto"})
	engine := NewEngine(reg)

	raw := models.RawEvent{Payload: "custom payload"}
	detection := models.DetectionResult{Format: "custom-proto"}

	parsed, err := engine.Parse(context.Background(), raw, detection)
	if err != nil {
		t.Fatalf("expected successful parse of custom parser: %v", err)
	}
	if parsed.Source.Identifier != "custom-sensor-01" {
		t.Errorf("expected identifier 'custom-sensor-01', got %q", parsed.Source.Identifier)
	}
	if parsed.Event.Action != "custom-action" {
		t.Errorf("expected action 'custom-action', got %q", parsed.Event.Action)
	}
}
