package parsers

import (
	"testing"

	"github.com/Krishiv-Mahajan/LogMorph/internal/models"
)

func TestJSONParser(t *testing.T) {
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

	event, err := parser.Parse(raw)
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
	if event.Source.Identifier != "custom-json-src" {
		t.Errorf("expected identifier 'custom-json-src', got %q", event.Source.Identifier)
	}
}
