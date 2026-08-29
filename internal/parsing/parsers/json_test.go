package parsers

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/Krishiv-Mahajan/LogMorph/internal/models"
)

func TestJSONParser_FlatStructure(t *testing.T) {
	parser := NewJSONParser()
	raw := models.RawEvent{
		Source: "firewall-02",
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

	event, err := parser.Parse(context.Background(), raw)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if event.Timestamp != "2026-08-29T10:15:00Z" {
		t.Errorf("expected timestamp '2026-08-29T10:15:00Z', got %q", event.Timestamp)
	}
	if event.Event.Action != "block" {
		t.Errorf("expected action 'block', got %q", event.Event.Action)
	}
	if event.Event.Severity != "high" {
		t.Errorf("expected severity 'high' for block action, got %q", event.Event.Severity)
	}
	if event.Network == nil {
		t.Fatal("expected non-nil network info")
	}
	if event.Network.Protocol != "TCP" {
		t.Errorf("expected protocol 'TCP', got %q", event.Network.Protocol)
	}
	if event.Network.SrcIP != "192.168.1.50" {
		t.Errorf("expected src_ip '192.168.1.50', got %q", event.Network.SrcIP)
	}
	if event.Network.SrcPort == nil || *event.Network.SrcPort != 45678 {
		t.Errorf("expected src_port 45678, got %v", event.Network.SrcPort)
	}
	if event.Network.DstIP != "10.0.0.20" {
		t.Errorf("expected dst_ip '10.0.0.20', got %q", event.Network.DstIP)
	}
	if event.Network.DstPort == nil || *event.Network.DstPort != 443 {
		t.Errorf("expected dst_port 443, got %v", event.Network.DstPort)
	}
	if event.Source.Identifier != "firewall-02" {
		t.Errorf("expected source identifier 'firewall-02', got %q", event.Source.Identifier)
	}
}

func TestJSONParser_Nested(t *testing.T) {
	parser := NewJSONParser()
	raw := models.RawEvent{
		Payload: `{
			"timestamp": "2026-08-28T18:30:12Z",
			"firewall": {
				"action": "deny",
				"protocol": "TCP"
			},
			"network": {
				"source": {
					"ip": "192.168.1.20",
					"port": 54321
				},
				"destination": {
					"ip": "10.0.0.15",
					"port": 443
				}
			}
		}`,
	}

	event, err := parser.Parse(context.Background(), raw)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if event.Timestamp != "2026-08-28T18:30:12Z" {
		t.Errorf("expected timestamp '2026-08-28T18:30:12Z', got %q", event.Timestamp)
	}
	if event.Event.Action != "deny" {
		t.Errorf("expected action 'deny', got %q", event.Event.Action)
	}
	if event.Event.Severity != "high" {
		t.Errorf("expected severity 'high', got %q", event.Event.Severity)
	}
	if event.Network == nil {
		t.Fatal("expected non-nil network info")
	}
	if event.Network.Protocol != "TCP" {
		t.Errorf("expected protocol 'TCP', got %q", event.Network.Protocol)
	}
	if event.Network.SrcIP != "192.168.1.20" {
		t.Errorf("expected src_ip '192.168.1.20', got %q", event.Network.SrcIP)
	}
	if event.Network.SrcPort == nil || *event.Network.SrcPort != 54321 {
		t.Errorf("expected src_port 54321, got %v", event.Network.SrcPort)
	}
	if event.Network.DstIP != "10.0.0.15" {
		t.Errorf("expected dst_ip '10.0.0.15', got %q", event.Network.DstIP)
	}
	if event.Network.DstPort == nil || *event.Network.DstPort != 443 {
		t.Errorf("expected dst_port 443, got %v", event.Network.DstPort)
	}
	if event.Source.Identifier != "json-source" {
		t.Errorf("expected default source identifier 'json-source', got %q", event.Source.Identifier)
	}
}

func TestJSONParser_PortConversions(t *testing.T) {
	parser := NewJSONParser()

	t.Run("Numeric string ports", func(t *testing.T) {
		raw := models.RawEvent{
			Payload: `{
				"timestamp": "2026-08-28T18:30:12Z",
				"action": "allow",
				"src_ip": "10.0.0.1",
				"src_port": "54321",
				"dst_ip": "10.0.0.2",
				"dst_port": "8080",
				"protocol": "TCP"
			}`,
		}
		event, err := parser.Parse(context.Background(), raw)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if event.Network.SrcPort == nil || *event.Network.SrcPort != 54321 {
			t.Errorf("expected src_port 54321, got %v", event.Network.SrcPort)
		}
		if event.Network.DstPort == nil || *event.Network.DstPort != 8080 {
			t.Errorf("expected dst_port 8080, got %v", event.Network.DstPort)
		}
	})

	t.Run("Invalid string port safely defaults to nil", func(t *testing.T) {
		raw := models.RawEvent{
			Payload: `{
				"timestamp": "2026-08-28T18:30:12Z",
				"action": "allow",
				"src_ip": "10.0.0.1",
				"src_port": "invalid_port_string",
				"dst_ip": "10.0.0.2",
				"dst_port": "",
				"protocol": "TCP"
			}`,
		}
		event, err := parser.Parse(context.Background(), raw)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if event.Network.SrcPort != nil {
			t.Errorf("expected nil src_port for invalid string, got %v", *event.Network.SrcPort)
		}
		if event.Network.DstPort != nil {
			t.Errorf("expected nil dst_port for empty string, got %v", *event.Network.DstPort)
		}
	})

	t.Run("Float64 integer port from JSON decoder", func(t *testing.T) {
		raw := models.RawEvent{
			Payload: `{
				"timestamp": "2026-08-28T18:30:12Z",
				"action": "allow",
				"src_ip": "10.0.0.1",
				"src_port": 443.0,
				"dst_ip": "10.0.0.2",
				"protocol": "TCP"
			}`,
		}
		event, err := parser.Parse(context.Background(), raw)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if event.Network.SrcPort == nil || *event.Network.SrcPort != 443 {
			t.Errorf("expected src_port 443, got %v", event.Network.SrcPort)
		}
	})

	t.Run("Unsupported port type (boolean) safely defaults to nil", func(t *testing.T) {
		raw := models.RawEvent{
			Payload: `{
				"timestamp": "2026-08-28T18:30:12Z",
				"action": "allow",
				"src_ip": "10.0.0.1",
				"src_port": true,
				"dst_ip": "10.0.0.2",
				"protocol": "TCP"
			}`,
		}
		event, err := parser.Parse(context.Background(), raw)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if event.Network.SrcPort != nil {
			t.Errorf("expected nil src_port for bool type, got %v", *event.Network.SrcPort)
		}
	})
}

func TestJSONParser_Aliases(t *testing.T) {
	parser := NewJSONParser()
	raw := models.RawEvent{
		Payload: `{
			"timestamp": "2026-08-29T10:15:00Z",
			"action": "deny",
			"source_ip": "172.16.0.5",
			"source_port": 50000,
			"destination_ip": "172.16.0.1",
			"destination_port": 22,
			"protocol": "TCP"
		}`,
	}

	event, err := parser.Parse(context.Background(), raw)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if event.Network.SrcIP != "172.16.0.5" {
		t.Errorf("expected src_ip '172.16.0.5', got %q", event.Network.SrcIP)
	}
	if event.Network.SrcPort == nil || *event.Network.SrcPort != 50000 {
		t.Errorf("expected src_port 50000, got %v", event.Network.SrcPort)
	}
	if event.Network.DstIP != "172.16.0.1" {
		t.Errorf("expected dst_ip '172.16.0.1', got %q", event.Network.DstIP)
	}
	if event.Network.DstPort == nil || *event.Network.DstPort != 22 {
		t.Errorf("expected dst_port 22, got %v", event.Network.DstPort)
	}
}

func TestJSONParser_Malformed(t *testing.T) {
	parser := NewJSONParser()

	t.Run("Empty payload returns error", func(t *testing.T) {
		raw := models.RawEvent{Payload: ""}
		_, err := parser.Parse(context.Background(), raw)
		if err == nil {
			t.Errorf("expected error on empty payload, got nil")
		}
	})

	t.Run("Whitespace-only payload returns error", func(t *testing.T) {
		raw := models.RawEvent{Payload: "   \t\n  "}
		_, err := parser.Parse(context.Background(), raw)
		if err == nil {
			t.Errorf("expected error on whitespace payload, got nil")
		}
	})

	t.Run("Invalid JSON syntax returns error", func(t *testing.T) {
		raw := models.RawEvent{Payload: `{ "action": "deny", `} // unclosed
		_, err := parser.Parse(context.Background(), raw)
		if err == nil {
			t.Errorf("expected error on unclosed JSON, got nil")
		}
	})

	t.Run("Truncated JSON array returns error", func(t *testing.T) {
		raw := models.RawEvent{Payload: `[{"action":`}
		_, err := parser.Parse(context.Background(), raw)
		if err == nil {
			t.Errorf("expected error on truncated JSON array, got nil")
		}
	})

	t.Run("Plain non-JSON string returns error", func(t *testing.T) {
		raw := models.RawEvent{Payload: "DENY TCP 192.168.1.1"}
		_, err := parser.Parse(context.Background(), raw)
		if err == nil {
			t.Errorf("expected error on plain non-JSON text, got nil")
		}
	})
}

func TestJSONParser_SeverityAndActionBehavior(t *testing.T) {
	parser := NewJSONParser()

	actionsHigh := []string{"deny", "DENY", "block", "BLOCK", "drop", "DROP"}
	for _, act := range actionsHigh {
		raw := models.RawEvent{
			Payload: `{"action": "` + act + `", "protocol": "TCP"}`,
		}
		event, err := parser.Parse(context.Background(), raw)
		if err != nil {
			t.Fatalf("unexpected error for action %q: %v", act, err)
		}
		if event.Event.Action != strings.ToLower(act) {
			t.Errorf("expected lower-cased action %q, got %q", strings.ToLower(act), event.Event.Action)
		}
		if event.Event.Severity != "high" {
			t.Errorf("expected severity 'high' for action %q, got %q", act, event.Event.Severity)
		}
	}

	actionsInfo := []string{"allow", "ALLOW", "permit", "accept"}
	for _, act := range actionsInfo {
		raw := models.RawEvent{
			Payload: `{"action": "` + act + `", "protocol": "UDP"}`,
		}
		event, err := parser.Parse(context.Background(), raw)
		if err != nil {
			t.Fatalf("unexpected error for action %q: %v", act, err)
		}
		if event.Event.Severity != "info" {
			t.Errorf("expected severity 'info' for action %q, got %q", act, event.Event.Severity)
		}
	}
}

func TestJSONParser_TimestampFallback(t *testing.T) {
	parser := NewJSONParser()
	raw := models.RawEvent{
		Payload: `{"action": "allow", "protocol": "TCP"}`,
	}

	event, err := parser.Parse(context.Background(), raw)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if _, err := time.Parse(time.RFC3339, event.Timestamp); err != nil {
		t.Errorf("expected valid RFC3339 timestamp fallback, got %q: %v", event.Timestamp, err)
	}
}

