package validation

import (
	"testing"
	"time"

	"github.com/Krishiv-Mahajan/LogMorph/internal/models"
)

func TestValidator_ValidEvent(t *testing.T) {
	val, err := NewValidator("")
	if err != nil {
		t.Fatalf("failed to initialize validator: %v", err)
	}

	port := 443
	event := &models.UniversalEvent{
		EventID:       "evt_test_123",
		SchemaVersion: "1.0",
		Timestamp:     time.Now().UTC().Format(time.RFC3339),
		Source: models.SourceInfo{
			Type:       "firewall",
			Vendor:     "example",
			Product:    "example-fw",
			Identifier: "fw-01",
		},
		Event: models.EventInfo{
			Category: "network",
			Action:   "deny",
			Severity: "high",
		},
		Network: &models.NetworkInfo{
			SrcIP:    "192.168.1.20",
			DstIP:    "10.0.0.15",
			DstPort:  &port,
			Protocol: "TCP",
		},
		Raw: models.RawInfo{
			Format:  "syslog",
			Message: "original log message",
		},
		Metadata: models.MetadataInfo{
			ParserVersion: "1.0",
			IngestedAt:    time.Now().UTC().Format(time.RFC3339),
		},
	}

	res := val.Validate(event)
	if !res.Valid {
		t.Fatalf("expected event to be valid, got errors: %+v", res.Errors)
	}
}

func TestValidator_InvalidEvent(t *testing.T) {
	val, err := NewValidator("")
	if err != nil {
		t.Fatalf("failed to initialize validator: %v", err)
	}

	// Missing required schema_version and metadata
	event := &models.UniversalEvent{
		EventID: "evt_invalid",
		Source: models.SourceInfo{
			Identifier: "fw-01",
		},
	}

	res := val.Validate(event)
	if res.Valid {
		t.Fatal("expected invalid event, but passed validation")
	}
	if len(res.Errors) == 0 {
		t.Fatal("expected validation errors, got none")
	}
}
