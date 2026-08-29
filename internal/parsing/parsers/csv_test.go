package parsers

import (
	"context"
	"testing"
	"time"

	"github.com/Krishiv-Mahajan/LogMorph/internal/models"
)

func TestCSVParser_StandardMVP(t *testing.T) {
	parser := NewCSVParser()
	raw := models.RawEvent{
		Source:  "firewall-01",
		Payload: "timestamp,action,protocol,src_ip,src_port,dst_ip,dst_port\n2026-08-28T18:30:12Z,deny,TCP,192.168.1.20,54321,10.0.0.15,443",
	}

	event, err := parser.Parse(context.Background(), raw)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// 1. Timestamp format
	if event.Timestamp != "2026-08-28T18:30:12Z" {
		t.Errorf("expected timestamp '2026-08-28T18:30:12Z', got %q", event.Timestamp)
	}

	// 2. Action, category, severity
	if event.Event.Action != "deny" {
		t.Errorf("expected action 'deny', got %q", event.Event.Action)
	}
	if event.Event.Category != "network" {
		t.Errorf("expected category 'network', got %q", event.Event.Category)
	}
	if event.Event.Severity != "high" {
		t.Errorf("expected severity 'high' for deny action, got %q", event.Event.Severity)
	}

	// 3. Network fields
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

	// 4. Source identifier
	if event.Source.Identifier != "firewall-01" {
		t.Errorf("expected source identifier 'firewall-01', got %q", event.Source.Identifier)
	}

	// 5. User field
	if event.User == nil || event.User.Username != nil {
		t.Errorf("expected nil username, got %+v", event.User)
	}
}

func TestCSVParser_ColumnOrdering(t *testing.T) {
	parser := NewCSVParser()
	// Scrambled column order: src_ip, dst_ip, dst_port, action, timestamp, protocol, src_port
	raw := models.RawEvent{
		Payload: "src_ip,dst_ip,dst_port,action,timestamp,protocol,src_port\n192.168.1.20,10.0.0.15,443,deny,2026-08-28T18:30:12Z,TCP,54321",
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

func TestCSVParser_HeaderNormalization(t *testing.T) {
	parser := NewCSVParser()
	// Headers with mixed case and leading/trailing whitespace
	raw := models.RawEvent{
		Payload: "  Timestamp , Action , PROTOCOL , Src_IP , Src_Port , Dst_IP , Dst_Port  \n2026-08-28T18:30:12Z,allow,UDP,10.0.0.1,1234,10.0.0.2,53",
	}

	event, err := parser.Parse(context.Background(), raw)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if event.Timestamp != "2026-08-28T18:30:12Z" {
		t.Errorf("expected timestamp '2026-08-28T18:30:12Z', got %q", event.Timestamp)
	}
	if event.Event.Action != "allow" {
		t.Errorf("expected action 'allow', got %q", event.Event.Action)
	}
	if event.Event.Severity != "info" {
		t.Errorf("expected severity 'info' for allow action, got %q", event.Event.Severity)
	}
	if event.Network.Protocol != "UDP" {
		t.Errorf("expected protocol 'UDP', got %q", event.Network.Protocol)
	}
	if event.Network.SrcIP != "10.0.0.1" {
		t.Errorf("expected src_ip '10.0.0.1', got %q", event.Network.SrcIP)
	}
	if event.Network.SrcPort == nil || *event.Network.SrcPort != 1234 {
		t.Errorf("expected src_port 1234, got %v", event.Network.SrcPort)
	}
	if event.Network.DstIP != "10.0.0.2" {
		t.Errorf("expected dst_ip '10.0.0.2', got %q", event.Network.DstIP)
	}
	if event.Network.DstPort == nil || *event.Network.DstPort != 53 {
		t.Errorf("expected dst_port 53, got %v", event.Network.DstPort)
	}
}

func TestCSVParser_QuotedValues(t *testing.T) {
	parser := NewCSVParser()
	raw := models.RawEvent{
		Payload: `"timestamp","action","protocol","src_ip","src_port","dst_ip","dst_port"` + "\n" +
			`"2026-08-28T18:30:12Z","deny","TCP","192.168.1.20","54321","10.0.0.15","443"`,
	}

	event, err := parser.Parse(context.Background(), raw)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if event.Event.Action != "deny" {
		t.Errorf("expected action 'deny', got %q", event.Event.Action)
	}
	if event.Network.SrcIP != "192.168.1.20" {
		t.Errorf("expected src_ip '192.168.1.20', got %q", event.Network.SrcIP)
	}
	if event.Network.SrcPort == nil || *event.Network.SrcPort != 54321 {
		t.Errorf("expected src_port 54321, got %v", event.Network.SrcPort)
	}
}

func TestCSVParser_Malformed(t *testing.T) {
	parser := NewCSVParser()

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

	t.Run("Header only without data row returns error", func(t *testing.T) {
		raw := models.RawEvent{Payload: "timestamp,action,protocol,src_ip,src_port,dst_ip,dst_port\n"}
		_, err := parser.Parse(context.Background(), raw)
		if err == nil {
			t.Errorf("expected error on header-only CSV, got nil")
		}
	})

	t.Run("Column count mismatch returns error", func(t *testing.T) {
		raw := models.RawEvent{
			Payload: "timestamp,action,protocol\n2026-08-28T18:30:12Z,deny,TCP,192.168.1.20,extra_val",
		}
		_, err := parser.Parse(context.Background(), raw)
		if err == nil {
			t.Errorf("expected error on column count mismatch, got nil")
		}
	})

	t.Run("Unclosed quotes return error", func(t *testing.T) {
		raw := models.RawEvent{
			Payload: `timestamp,action` + "\n" + `"2026-08-28T18:30:12Z,deny`,
		}
		_, err := parser.Parse(context.Background(), raw)
		if err == nil {
			t.Errorf("expected error on unclosed quote in CSV, got nil")
		}
	})

	t.Run("Invalid numeric port defaults to nil without error or panic", func(t *testing.T) {
		raw := models.RawEvent{
			Payload: "timestamp,action,protocol,src_ip,src_port,dst_ip,dst_port\n2026-08-28T18:30:12Z,deny,TCP,192.168.1.20,not_a_port,10.0.0.15,",
		}
		event, err := parser.Parse(context.Background(), raw)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if event.Network.SrcPort != nil {
			t.Errorf("expected nil src_port for invalid string, got %v", *event.Network.SrcPort)
		}
		if event.Network.DstPort != nil {
			t.Errorf("expected nil dst_port for empty value, got %v", *event.Network.DstPort)
		}
	})
}

func TestCSVParser_MultipleRows(t *testing.T) {
	parser := NewCSVParser()
	// CSV containing multiple data rows: verifies first data row is parsed for this event envelope
	raw := models.RawEvent{
		Payload: "timestamp,action,protocol,src_ip,src_port,dst_ip,dst_port\n" +
			"2026-08-28T18:30:12Z,deny,TCP,192.168.1.20,54321,10.0.0.15,443\n" +
			"2026-08-28T18:30:13Z,allow,UDP,192.168.1.21,12345,10.0.0.16,53",
	}

	event, err := parser.Parse(context.Background(), raw)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if event.Timestamp != "2026-08-28T18:30:12Z" {
		t.Errorf("expected first row timestamp '2026-08-28T18:30:12Z', got %q", event.Timestamp)
	}
	if event.Event.Action != "deny" {
		t.Errorf("expected first row action 'deny', got %q", event.Event.Action)
	}
	if event.Network.SrcIP != "192.168.1.20" {
		t.Errorf("expected first row src_ip '192.168.1.20', got %q", event.Network.SrcIP)
	}
}

func TestCSVParser_OptionalFields(t *testing.T) {
	parser := NewCSVParser()

	t.Run("Source, category, severity, and username columns", func(t *testing.T) {
		raw := models.RawEvent{
			Payload: "timestamp,action,protocol,src_ip,dst_ip,source,category,severity,username\n" +
				"2026-08-28T18:30:12Z,drop,TCP,10.0.0.5,10.0.0.1,custom-firewall-99,network_security,critical,admin_user",
		}

		event, err := parser.Parse(context.Background(), raw)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if event.Source.Identifier != "custom-firewall-99" {
			t.Errorf("expected source identifier 'custom-firewall-99', got %q", event.Source.Identifier)
		}
		if event.Event.Category != "network_security" {
			t.Errorf("expected category 'network_security', got %q", event.Event.Category)
		}
		if event.Event.Severity != "critical" {
			t.Errorf("expected severity 'critical', got %q", event.Event.Severity)
		}
		if event.User == nil || event.User.Username == nil || *event.User.Username != "admin_user" {
			t.Errorf("expected username 'admin_user', got %+v", event.User)
		}
	})

	t.Run("Timestamp omitted generates RFC3339 fallback", func(t *testing.T) {
		raw := models.RawEvent{
			Payload: "action,protocol,src_ip,dst_ip\ndeny,TCP,192.168.1.20,10.0.0.15",
		}

		event, err := parser.Parse(context.Background(), raw)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if _, err := time.Parse(time.RFC3339, event.Timestamp); err != nil {
			t.Errorf("expected valid RFC3339 fallback timestamp, got %q: %v", event.Timestamp, err)
		}
	})
}

