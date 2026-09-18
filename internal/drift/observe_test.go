package drift

import (
	"errors"
	"testing"

	"github.com/Krishiv-Mahajan/LogMorph/internal/contract"
)

func observedType(t *testing.T, observation Observation, name string) contract.Type {
	t.Helper()

	field, ok := observation.Lookup(name)
	if !ok {
		t.Fatalf("expected %q to be observed; got %v", name, observation.Names())
	}
	return field.Type
}

func TestObserveJSONFlattensNestedObjects(t *testing.T) {
	payload := `{
	  "timestamp": "2026-08-28T18:30:12Z",
	  "firewall": {"action": "deny", "protocol": "TCP"},
	  "network": {"source": {"ip": "192.168.1.20", "port": 54321}},
	  "severity": 5,
	  "blocked": true
	}`

	observation, err := Observe("json", payload)
	if err != nil {
		t.Fatalf("observe failed: %v", err)
	}

	if observedType(t, observation, "timestamp") != contract.TypeString {
		t.Error("expected timestamp to be a string")
	}
	if observedType(t, observation, "firewall") != contract.TypeObject {
		t.Error("expected the container itself to be observed")
	}
	if observedType(t, observation, "firewall.action") != contract.TypeString {
		t.Error("expected firewall.action to be a string")
	}
	if observedType(t, observation, "network.source.port") != contract.TypeInteger {
		t.Error("expected a numeric port to be observed as an integer")
	}
	if observedType(t, observation, "severity") != contract.TypeInteger {
		t.Error("expected a numeric severity to be an integer")
	}
	if observedType(t, observation, "blocked") != contract.TypeBoolean {
		t.Error("expected a boolean to be observed as a boolean")
	}

	// Field names are normalized and ordered.
	names := observation.Names()
	for i := 1; i < len(names); i++ {
		if names[i-1] > names[i] {
			t.Fatalf("expected sorted field names, got %v", names)
		}
	}
}

// TestObserveJSONTypesNumericStrings — a port arriving as a JSON string must not
// look like a type change.
func TestObserveJSONTypesNumericStrings(t *testing.T) {
	observation, err := Observe("json", `{"src_port": "443", "action": "deny"}`)
	if err != nil {
		t.Fatalf("observe failed: %v", err)
	}

	if observedType(t, observation, "src_port") != contract.TypeInteger {
		t.Error("expected a numeric string to be observed as an integer")
	}
	if observedType(t, observation, "action") != contract.TypeString {
		t.Error("expected a non-numeric string to be observed as a string")
	}
}

func TestObserveJSONTopLevelArrayIsStructural(t *testing.T) {
	observation, err := Observe("json", `[{"action":"deny"}]`)
	if err != nil {
		t.Fatalf("observe failed: %v", err)
	}

	if len(observation.Fields) != 1 || observation.Fields[0].Type != contract.TypeArray {
		t.Fatalf("expected a single array field, got %+v", observation.Fields)
	}
}

func TestObserveJSONRejectsMalformed(t *testing.T) {
	if _, err := Observe("json", `{"broken": `); err == nil {
		t.Error("expected an error for malformed JSON")
	}
	if _, err := Observe("json", "   "); err == nil {
		t.Error("expected an error for an empty payload")
	}
}

func TestObserveCSVUsesHeaderAndInfersTypes(t *testing.T) {
	payload := "timestamp,action,src_port,dst_port,empty\n" +
		"2026-08-28T18:30:12Z,deny,54321,443,\n"

	observation, err := Observe("csv", payload)
	if err != nil {
		t.Fatalf("observe failed: %v", err)
	}

	if observedType(t, observation, "action") != contract.TypeString {
		t.Error("expected action to be a string")
	}
	if observedType(t, observation, "src_port") != contract.TypeInteger {
		t.Error("expected a numeric column to be an integer")
	}
	// An empty cell carries no evidence and must not look like a type change.
	if observedType(t, observation, "empty") != contract.TypeUnknown {
		t.Error("expected an empty column to carry no type evidence")
	}
}

// TestObserveCSVMergesColumnEvidence — a column that is sometimes numeric and
// sometimes not is a string column, not a drifting integer.
func TestObserveCSVMergesColumnEvidence(t *testing.T) {
	payload := "src_port\n443\n\"not-a-port\"\n"

	observation, err := Observe("csv", payload)
	if err != nil {
		t.Fatalf("observe failed: %v", err)
	}

	if observedType(t, observation, "src_port") != contract.TypeString {
		t.Error("expected mixed evidence to resolve to a string")
	}
}

func TestObserveSyslogUsesKeyValuePairs(t *testing.T) {
	payload := "Aug 28 18:30:12 firewall01 DENY TCP SRC=192.168.1.20:54321 DST=10.0.0.15:443"

	observation, err := Observe("syslog", payload)
	if err != nil {
		t.Fatalf("observe failed: %v", err)
	}

	names := observation.Names()
	if len(names) != 2 {
		t.Fatalf("expected the two key=value pairs, got %v", names)
	}
	if observedType(t, observation, "SRC") != contract.TypeString {
		t.Error("expected the ip:port form to be observed as a string")
	}
	if observedType(t, observation, "DST") != contract.TypeString {
		t.Error("expected the ip:port form to be observed as a string")
	}
}

func TestObserveSyslogNumericPort(t *testing.T) {
	observation, err := Observe("syslog", "Aug 28 18:30:12 host ACTION=deny SPT=12345")
	if err != nil {
		t.Fatalf("observe failed: %v", err)
	}

	if observedType(t, observation, "SPT") != contract.TypeInteger {
		t.Error("expected a numeric KV value to be observed as an integer")
	}
	if observedType(t, observation, "ACTION") != contract.TypeString {
		t.Error("expected a word KV value to be observed as a string")
	}
}

func TestObserveUnsupportedFormat(t *testing.T) {
	if _, err := Observe("xml", "<log/>"); !errors.Is(err, ErrUnsupportedFormat) {
		t.Errorf("expected ErrUnsupportedFormat, got %v", err)
	}
}
