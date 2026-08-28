package parsers

import (
	"testing"

	"github.com/Krishiv-Mahajan/LogMorph/internal/models"
)

func TestSyslogParser(t *testing.T) {
	parser := NewSyslogParser()
	raw := models.RawEvent{
		Source:  "firewall01",
		Payload: "Aug 28 18:30:12 firewall01 DENY TCP SRC=192.168.1.20:54321 DST=10.0.0.15:443",
	}

	event, err := parser.Parse(raw)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
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
	if event.Source.Identifier != "firewall01" {
		t.Errorf("expected source identifier 'firewall01', got %q", event.Source.Identifier)
	}
}
