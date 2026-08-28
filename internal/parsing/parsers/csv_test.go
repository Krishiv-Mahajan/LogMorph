package parsers

import (
	"context"
	"testing"

	"github.com/Krishiv-Mahajan/LogMorph/internal/models"
)

func TestCSVParser(t *testing.T) {
	parser := NewCSVParser()
	raw := models.RawEvent{
		Source:  "csv-sensor",
		Payload: "timestamp,action,protocol,src_ip,src_port,dst_ip,dst_port\n2026-08-28T18:30:12Z,deny,TCP,192.168.1.20,54321,10.0.0.15,443",
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

func TestCSVParser_Malformed(t *testing.T) {
	parser := NewCSVParser()
	raw := models.RawEvent{
		Payload: "timestamp,action\n2026-08-28T18:30:12Z,deny,extra_col",
	}

	_, err := parser.Parse(context.Background(), raw)
	if err == nil {
		t.Fatal("expected error on malformed CSV columns mismatch, got nil")
	}
}
