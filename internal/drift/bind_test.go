package drift

import (
	"testing"

	"github.com/Krishiv-Mahajan/LogMorph/internal/contract"
	"github.com/Krishiv-Mahajan/LogMorph/internal/models"
)

// csvAliasContract declares a synonym the CSV parser itself does not implement,
// which is precisely the case the binder exists for.
func csvAliasContract() contract.Contract {
	return contract.Contract{Fields: []contract.Field{
		{Name: "src_ip", Aliases: []string{"source_ip"}, Type: contract.TypeString, Target: "network.src_ip", Optional: true},
		{Name: "dst_port", Aliases: []string{"destination_port"}, Type: contract.TypeInteger, Target: "network.dst_port", Optional: true},
		{Name: "device_uuid", Type: contract.TypeString, Optional: true},
	}}.Normalized()
}

func TestBindFillsAliasValues(t *testing.T) {
	parsed := &models.ParsedEvent{Network: &models.NetworkInfo{Protocol: "TCP"}}
	observation := Observation{Format: "csv", Fields: []ObservedField{
		{Name: "source_ip", Type: contract.TypeString, Value: "192.168.1.20"},
		{Name: "destination_port", Type: contract.TypeInteger, Value: "443"},
	}}

	bindings := Bind(parsed, observation, csvAliasContract())

	if parsed.Network.SrcIP != "192.168.1.20" {
		t.Errorf("expected the alias to fill SrcIP, got %q", parsed.Network.SrcIP)
	}
	if parsed.Network.DstPort == nil || *parsed.Network.DstPort != 443 {
		t.Errorf("expected the alias to fill DstPort, got %v", parsed.Network.DstPort)
	}
	if len(bindings) != 2 {
		t.Fatalf("expected 2 bindings, got %d: %+v", len(bindings), bindings)
	}
	// The binding names both what arrived and what it resolved to, so the
	// contribution is auditable.
	if bindings[0].Field != "source_ip" || bindings[0].Canonical != "src_ip" {
		t.Errorf("expected source_ip to bind to src_ip, got %+v", bindings[0])
	}
	if bindings[0].Target != "network.src_ip" {
		t.Errorf("expected the binding to name its target, got %+v", bindings[0])
	}
}

// TestBindNeverOverwritesTheParser — a value the parser produced always wins.
func TestBindNeverOverwritesTheParser(t *testing.T) {
	parsed := &models.ParsedEvent{
		Network: &models.NetworkInfo{SrcIP: "10.9.9.9"},
	}
	observation := Observation{Format: "csv", Fields: []ObservedField{
		{Name: "source_ip", Type: contract.TypeString, Value: "192.168.1.20"},
	}}

	bindings := Bind(parsed, observation, csvAliasContract())

	if parsed.Network.SrcIP != "10.9.9.9" {
		t.Errorf("expected the parser's value to survive, got %q", parsed.Network.SrcIP)
	}
	if len(bindings) != 0 {
		t.Errorf("expected no bindings, got %+v", bindings)
	}
}

// TestBindIgnoresUndeclaredFields — binding requires knowing what a field means,
// and an undeclared field has no declared meaning.
func TestBindIgnoresUndeclaredFields(t *testing.T) {
	parsed := &models.ParsedEvent{Network: &models.NetworkInfo{}}
	observation := Observation{Format: "csv", Fields: []ObservedField{
		{Name: "device_uuid", Type: contract.TypeString, Value: "abc-123"},
		{Name: "mystery_ip", Type: contract.TypeString, Value: "10.0.0.1"},
	}}

	bindings := Bind(parsed, observation, csvAliasContract())

	if len(bindings) != 0 {
		t.Errorf("expected no bindings for declared-but-unbound or unknown fields, got %+v", bindings)
	}
	if parsed.Network.SrcIP != "" {
		t.Error("expected an unknown field to leave the event untouched")
	}
}

// TestBindIgnoresCanonicalNames — canonical names are the parser's job. If the
// parser left them empty, the raw value was not usable and the binder must not
// second-guess it.
func TestBindIgnoresCanonicalNames(t *testing.T) {
	parsed := &models.ParsedEvent{Network: &models.NetworkInfo{}}
	observation := Observation{Format: "csv", Fields: []ObservedField{
		{Name: "src_ip", Type: contract.TypeString, Value: "192.168.1.20"},
	}}

	bindings := Bind(parsed, observation, csvAliasContract())

	if len(bindings) != 0 {
		t.Errorf("expected canonical names not to be bound, got %+v", bindings)
	}
	if parsed.Network.SrcIP != "" {
		t.Error("expected the canonical field to remain the parser's responsibility")
	}
}

// TestBindRefusesUnusableValues — a value that cannot be a port is not written
// as one.
func TestBindRefusesUnusableValues(t *testing.T) {
	parsed := &models.ParsedEvent{Network: &models.NetworkInfo{}}
	observation := Observation{Format: "csv", Fields: []ObservedField{
		{Name: "destination_port", Type: contract.TypeInteger, Value: "tcp/443"},
		{Name: "destination_port_2", Type: contract.TypeInteger, Value: "999999"},
	}}

	bindings := Bind(parsed, observation, csvAliasContract())

	if len(bindings) != 0 {
		t.Errorf("expected unusable ports not to be bound, got %+v", bindings)
	}
	if parsed.Network.DstPort != nil {
		t.Errorf("expected DstPort to stay nil, got %v", *parsed.Network.DstPort)
	}
}

// TestBindFillsScalarTargets covers the non-network targets.
func TestBindFillsScalarTargets(t *testing.T) {
	fieldContract := contract.Contract{Fields: []contract.Field{
		{Name: "act", Aliases: []string{"firewall.action"}, Type: contract.TypeString, Target: "event.action", Optional: true},
		{Name: "sev", Aliases: []string{"firewall.severity"}, Type: contract.TypeString, Target: "event.severity", Optional: true},
		{Name: "who", Aliases: []string{"user_name"}, Type: contract.TypeString, Target: "user.username", Optional: true},
		{Name: "when", Aliases: []string{"event_time"}, Type: contract.TypeString, Target: "timestamp", Optional: true},
	}}.Normalized()

	parsed := &models.ParsedEvent{}
	observation := Observation{Format: "json", Fields: []ObservedField{
		{Name: "firewall.action", Type: contract.TypeString, Value: "deny"},
		{Name: "firewall.severity", Type: contract.TypeString, Value: "high"},
		{Name: "user_name", Type: contract.TypeString, Value: "alice"},
		{Name: "event_time", Type: contract.TypeString, Value: "2026-08-28T18:30:12Z"},
	}}

	bindings := Bind(parsed, observation, fieldContract)

	if parsed.Event.Action != "deny" || parsed.Event.Severity != "high" {
		t.Errorf("expected event fields to be bound, got %+v", parsed.Event)
	}
	if parsed.User == nil || parsed.User.Username == nil || *parsed.User.Username != "alice" {
		t.Error("expected the username to be bound")
	}
	if parsed.Timestamp != "2026-08-28T18:30:12Z" {
		t.Errorf("expected the timestamp to be bound, got %q", parsed.Timestamp)
	}
	if len(bindings) != 4 {
		t.Errorf("expected 4 bindings, got %+v", bindings)
	}
}

func TestBindHandlesNilParsedEvent(t *testing.T) {
	if bindings := Bind(nil, Observation{}, csvAliasContract()); bindings != nil {
		t.Errorf("expected no bindings for a nil event, got %+v", bindings)
	}
}
