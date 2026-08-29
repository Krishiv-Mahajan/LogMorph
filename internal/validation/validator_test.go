package validation

import (
	"encoding/json"
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

func validEvent() models.UniversalEvent {
	srcPort := 54321
	dstPort := 443
	return models.UniversalEvent{
		EventID:       "evt_valid_123",
		SchemaVersion: "1.0",
		Timestamp:     "2026-08-28T18:30:12Z",
		Source: models.SourceInfo{
			Type:       "firewall",
			Vendor:     "Cisco",
			Product:    "ASA",
			Identifier: "fw-01",
		},
		Event: models.EventInfo{
			Category: "network",
			Action:   "deny",
			Severity: "high",
		},
		Network: &models.NetworkInfo{
			SrcIP:    "192.168.1.20",
			SrcPort:  &srcPort,
			DstIP:    "10.0.0.15",
			DstPort:  &dstPort,
			Protocol: "TCP",
		},
		Raw: models.RawInfo{
			Format:  "syslog",
			Message: "original log message",
		},
		Metadata: models.MetadataInfo{
			ParserVersion: "1.0",
			IngestedAt:    "2026-08-28T18:30:12Z",
		},
	}
}

func validMap() map[string]any {
	return map[string]any{
		"event_id":       "evt_valid_123",
		"schema_version": "1.0",
		"timestamp":      "2026-08-28T18:30:12Z",
		"source": map[string]any{
			"type":       "firewall",
			"vendor":     "Cisco",
			"product":    "ASA",
			"identifier": "fw-01",
		},
		"event": map[string]any{
			"category": "network",
			"action":   "deny",
			"severity": "high",
		},
		"network": map[string]any{
			"src_ip":   "192.168.1.20",
			"src_port": 54321,
			"dst_ip":   "10.0.0.15",
			"dst_port": 443,
			"protocol": "TCP",
		},
		"raw": map[string]any{
			"format":  "syslog",
			"message": "original log message",
		},
		"metadata": map[string]any{
			"parser_version": "1.0",
			"ingested_at":    "2026-08-28T18:30:12Z",
		},
	}
}

func TestValidator_InvalidEvents(t *testing.T) {
	val, err := NewValidator("")
	if err != nil {
		t.Fatalf("failed to initialize validator: %v", err)
	}

	tests := []struct {
		name     string
		getEvent func() *models.UniversalEvent
		getJSON  func() string
	}{
		{
			name: "1. Missing event_id (empty string)",
			getEvent: func() *models.UniversalEvent {
				e := validEvent()
				e.EventID = ""
				return &e
			},
		},
		{
			name: "2. Missing schema_version (empty string)",
			getEvent: func() *models.UniversalEvent {
				e := validEvent()
				e.SchemaVersion = ""
				return &e
			},
		},
		{
			name: "3. Invalid schema_version (2.0)",
			getEvent: func() *models.UniversalEvent {
				e := validEvent()
				e.SchemaVersion = "2.0"
				return &e
			},
		},
		{
			name: "4. Missing timestamp",
			getJSON: func() string {
				m := validMap()
				delete(m, "timestamp")
				b, _ := json.Marshal(m)
				return string(b)
			},
		},
		{
			name: "5. Missing source",
			getJSON: func() string {
				m := validMap()
				delete(m, "source")
				b, _ := json.Marshal(m)
				return string(b)
			},
		},
		{
			name: "6. Missing event",
			getJSON: func() string {
				m := validMap()
				delete(m, "event")
				b, _ := json.Marshal(m)
				return string(b)
			},
		},
		{
			name: "7. Missing raw",
			getJSON: func() string {
				m := validMap()
				delete(m, "raw")
				b, _ := json.Marshal(m)
				return string(b)
			},
		},
		{
			name: "8. Missing raw.format",
			getJSON: func() string {
				m := validMap()
				m["raw"] = map[string]any{"message": "some log"}
				b, _ := json.Marshal(m)
				return string(b)
			},
		},
		{
			name: "9. Missing raw.message",
			getJSON: func() string {
				m := validMap()
				m["raw"] = map[string]any{"format": "syslog"}
				b, _ := json.Marshal(m)
				return string(b)
			},
		},
		{
			name: "10. Missing metadata",
			getJSON: func() string {
				m := validMap()
				delete(m, "metadata")
				b, _ := json.Marshal(m)
				return string(b)
			},
		},
		{
			name: "11. Network source port below 0",
			getEvent: func() *models.UniversalEvent {
				e := validEvent()
				invalidPort := -1
				e.Network.SrcPort = &invalidPort
				return &e
			},
		},
		{
			name: "12. Network destination port above 65535",
			getEvent: func() *models.UniversalEvent {
				e := validEvent()
				invalidPort := 70000
				e.Network.DstPort = &invalidPort
				return &e
			},
		},
		{
			name: "13. Wrong type for numeric port (string instead of integer)",
			getJSON: func() string {
				m := validMap()
				m["network"] = map[string]any{
					"dst_port": "443",
				}
				b, _ := json.Marshal(m)
				return string(b)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var res ValidationResult
			if tt.getEvent != nil {
				res = val.Validate(tt.getEvent())
			} else if tt.getJSON != nil {
				res = val.ValidateBytes([]byte(tt.getJSON()))
			}

			if res.Valid {
				t.Errorf("case %q: expected validation failure, but validation passed", tt.name)
			}
			if len(res.Errors) == 0 {
				t.Errorf("case %q: expected non-empty validation errors list, got 0 errors", tt.name)
			}
		})
	}
}
