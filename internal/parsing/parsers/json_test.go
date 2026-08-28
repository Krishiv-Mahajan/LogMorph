package parsers

import (
	"context"
	"testing"

	"github.com/Krishiv-Mahajan/LogMorph/internal/models"
)

func TestJSONParser_Nested(t *testing.T) {
	parser := NewJSONParser()
	raw := models.RawEvent{
		Source: "custom-json-src",
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
}

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
}
