package parsers

import (
	"context"
	"testing"
	"time"

	"github.com/Krishiv-Mahajan/LogMorph/internal/models"
)

func TestSyslogParser_StandardMVP(t *testing.T) {
	parser := NewSyslogParser()
	raw := models.RawEvent{
		Payload: "Aug 28 18:30:12 firewall01 DENY TCP SRC=192.168.1.20:54321 DST=10.0.0.15:443",
	}

	event, err := parser.Parse(context.Background(), raw)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// 1. Timestamp format
	if _, err := time.Parse(time.RFC3339, event.Timestamp); err != nil {
		t.Errorf("timestamp %q is not valid RFC3339: %v", event.Timestamp, err)
	}

	// 2. Source identifier from header
	if event.Source.Identifier != "firewall01" {
		t.Errorf("expected source identifier 'firewall01', got %q", event.Source.Identifier)
	}
	if event.Source.Type != "firewall" {
		t.Errorf("expected source type 'firewall', got %q", event.Source.Type)
	}

	// 3. Action and category
	if event.Event.Action != "deny" {
		t.Errorf("expected action 'deny', got %q", event.Event.Action)
	}
	if event.Event.Category != "network" {
		t.Errorf("expected category 'network', got %q", event.Event.Category)
	}
	if event.Event.Severity != "high" {
		t.Errorf("expected severity 'high', got %q", event.Event.Severity)
	}

	// 4. Network fields
	if event.Network == nil {
		t.Fatal("expected non-nil Network info")
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

	// 5. User field
	if event.User == nil || event.User.Username != nil {
		t.Errorf("expected nil username, got %+v", event.User)
	}
}

func TestSyslogParser_SpaceSeparatedPorts(t *testing.T) {
	parser := NewSyslogParser()
	raw := models.RawEvent{
		Payload: "Aug 28 18:30:12 firewall01 DENY TCP SRC=192.168.1.20 SPT=54321 DST=10.0.0.15 DPT=443",
	}

	event, err := parser.Parse(context.Background(), raw)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if event.Network == nil {
		t.Fatal("expected non-nil Network info")
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

func TestSyslogParser_KeyValueVariants(t *testing.T) {
	parser := NewSyslogParser()

	t.Run("Explicit ACTION and PROTO keys", func(t *testing.T) {
		raw := models.RawEvent{
			Payload: "Aug 28 18:30:12 firewall01 ACTION=DENY PROTO=TCP SRC=192.168.1.20:54321 DST=10.0.0.15:443",
		}
		event, err := parser.Parse(context.Background(), raw)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if event.Event.Action != "deny" {
			t.Errorf("expected action 'deny', got %q", event.Event.Action)
		}
		if event.Network.Protocol != "TCP" {
			t.Errorf("expected protocol 'TCP', got %q", event.Network.Protocol)
		}
		if event.Event.Severity != "high" {
			t.Errorf("expected severity 'high', got %q", event.Event.Severity)
		}
	})

	t.Run("ALLOW action variant with INFO severity", func(t *testing.T) {
		raw := models.RawEvent{
			Payload: "Aug 28 18:30:12 firewall01 ALLOW UDP SRC=10.0.0.5:1234 DST=10.0.0.1:53",
		}
		event, err := parser.Parse(context.Background(), raw)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if event.Event.Action != "allow" {
			t.Errorf("expected action 'allow', got %q", event.Event.Action)
		}
		if event.Network.Protocol != "UDP" {
			t.Errorf("expected protocol 'UDP', got %q", event.Network.Protocol)
		}
		if event.Event.Severity != "info" {
			t.Errorf("expected severity 'info', got %q", event.Event.Severity)
		}
	})
}

func TestSyslogParser_CaseHandling(t *testing.T) {
	parser := NewSyslogParser()
	raw := models.RawEvent{
		Payload: "Aug 28 18:30:12 firewall01 deny tcp src=192.168.1.20:54321 dst=10.0.0.15:443",
	}

	event, err := parser.Parse(context.Background(), raw)
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
}

func TestSyslogParser_InvalidAndEmptyPayload(t *testing.T) {
	parser := NewSyslogParser()

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

	t.Run("Malformed log does not panic", func(t *testing.T) {
		raw := models.RawEvent{
			Payload: "not a valid syslog format ::: ### === 12345",
		}
		event, err := parser.Parse(context.Background(), raw)
		if err != nil {
			// Controlled error is acceptable
			return
		}
		if event == nil {
			t.Fatal("expected non-nil event if err is nil")
		}
	})
}

func TestSyslogParser_SourceFallback(t *testing.T) {
	parser := NewSyslogParser()

	t.Run("Fallback to RawEvent.Source when header lacks hostname", func(t *testing.T) {
		raw := models.RawEvent{
			Source:  "edge-router-01",
			Payload: "DENY TCP SRC=192.168.1.20:54321 DST=10.0.0.15:443",
		}

		event, err := parser.Parse(context.Background(), raw)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if event.Source.Identifier != "edge-router-01" {
			t.Errorf("expected source identifier 'edge-router-01', got %q", event.Source.Identifier)
		}
	})

	t.Run("Fallback to unknown-host when both header hostname and RawEvent.Source are empty", func(t *testing.T) {
		raw := models.RawEvent{
			Source:  "",
			Payload: "DENY TCP SRC=192.168.1.20:54321 DST=10.0.0.15:443",
		}

		event, err := parser.Parse(context.Background(), raw)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if event.Source.Identifier != "unknown-host" {
			t.Errorf("expected source identifier 'unknown-host', got %q", event.Source.Identifier)
		}
	})
}

func TestSyslogParser_RFC5424PriorityPrefix(t *testing.T) {
	parser := NewSyslogParser()
	raw := models.RawEvent{
		Payload: "<134>Aug 28 18:30:12 firewall01 DENY TCP SRC=192.168.1.20:54321 DST=10.0.0.15:443",
	}

	event, err := parser.Parse(context.Background(), raw)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if event.Source.Identifier != "firewall01" {
		t.Errorf("expected source identifier 'firewall01', got %q", event.Source.Identifier)
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
