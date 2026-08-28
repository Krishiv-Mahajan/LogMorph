package normalization

import (
	"strings"
	"testing"
	"time"

	"github.com/Krishiv-Mahajan/LogMorph/internal/models"
	"github.com/Krishiv-Mahajan/LogMorph/internal/validation"
)

func TestNormalizer(t *testing.T) {
	normalizer := NewNormalizer()

	nowStr := "2026-08-28T18:30:12Z"
	srcPort := 54321
	dstPort := 443

	raw := models.RawEvent{
		EventID:    "evt_norm_123",
		ReceivedAt: nowStr,
		Format:     "syslog",
		Source:     "firewall-01",
		Payload:    "Aug 28 18:30:12 firewall01 DENY TCP SRC=192.168.1.20:54321 DST=10.0.0.15:443",
	}

	parsed := &models.ParsedEvent{
		Timestamp: "2026-08-28T18:30:12Z",
		Source: models.SourceInfo{
			Type:       "firewall",
			Vendor:     "Cisco",
			Product:    "ASA",
			Identifier: "firewall-01",
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
	}

	detectionRes := models.DetectionResult{
		Format:     "syslog",
		SourceType: "firewall",
		Confidence: 1.0,
	}

	universal, err := normalizer.Normalize(raw, parsed, detectionRes)
	if err != nil {
		t.Fatalf("normalizer error: %v", err)
	}

	// 1. EventID is preserved.
	if universal.EventID != "evt_norm_123" {
		t.Errorf("expected EventID 'evt_norm_123', got %q", universal.EventID)
	}

	// 2. SchemaVersion is "1.0".
	if universal.SchemaVersion != "1.0" {
		t.Errorf("expected SchemaVersion '1.0', got %q", universal.SchemaVersion)
	}

	// 3. Raw.Format is "syslog".
	if universal.Raw.Format != "syslog" {
		t.Errorf("expected Raw.Format 'syslog', got %q", universal.Raw.Format)
	}

	// 4. Raw.Message is EXACTLY equal to RawEvent.Payload.
	if universal.Raw.Message != raw.Payload {
		t.Errorf("expected Raw.Message %q, got %q", raw.Payload, universal.Raw.Message)
	}

	// 5. Source fields are preserved.
	if universal.Source.Type != "firewall" {
		t.Errorf("expected Source.Type 'firewall', got %q", universal.Source.Type)
	}
	if universal.Source.Vendor != "Cisco" {
		t.Errorf("expected Source.Vendor 'Cisco', got %q", universal.Source.Vendor)
	}
	if universal.Source.Product != "ASA" {
		t.Errorf("expected Source.Product 'ASA', got %q", universal.Source.Product)
	}
	if universal.Source.Identifier != "firewall-01" {
		t.Errorf("expected Source.Identifier 'firewall-01', got %q", universal.Source.Identifier)
	}

	// 6. Event fields are preserved.
	if universal.Event.Category != "network" {
		t.Errorf("expected Event.Category 'network', got %q", universal.Event.Category)
	}
	if universal.Event.Action != "deny" {
		t.Errorf("expected Event.Action 'deny', got %q", universal.Event.Action)
	}
	if universal.Event.Severity != "high" {
		t.Errorf("expected Event.Severity 'high', got %q", universal.Event.Severity)
	}

	// 7. Source IP is preserved.
	if universal.Network == nil || universal.Network.SrcIP != "192.168.1.20" {
		t.Errorf("expected Network.SrcIP '192.168.1.20', got %v", universal.Network)
	}

	// 8. Destination IP is preserved.
	if universal.Network == nil || universal.Network.DstIP != "10.0.0.15" {
		t.Errorf("expected Network.DstIP '10.0.0.15', got %v", universal.Network)
	}

	// 9. Source port is preserved.
	if universal.Network == nil || universal.Network.SrcPort == nil || *universal.Network.SrcPort != 54321 {
		t.Errorf("expected Network.SrcPort 54321, got %v", universal.Network)
	}

	// 10. Destination port is preserved.
	if universal.Network == nil || universal.Network.DstPort == nil || *universal.Network.DstPort != 443 {
		t.Errorf("expected Network.DstPort 443, got %v", universal.Network)
	}

	// 11. Protocol is preserved.
	if universal.Network == nil || universal.Network.Protocol != "TCP" {
		t.Errorf("expected Network.Protocol 'TCP', got %v", universal.Network)
	}
}

func TestNormalizer_RawPayloadPreserved(t *testing.T) {
	normalizer := NewNormalizer()

	tests := []struct {
		name    string
		payload string
		format  string
	}{
		{
			name:    "Normal security log",
			payload: "Aug 28 18:30:12 firewall01 DENY TCP SRC=192.168.1.20:54321 DST=10.0.0.15:443",
			format:  "syslog",
		},
		{
			name:    "Multiple spaces",
			payload: "Aug 28 18:30:12  firewall01   DENY   TCP   SRC=192.168.1.20:54321",
			format:  "syslog",
		},
		{
			name:    "Tabs",
			payload: "firewall01\tDENY\tTCP\tSRC=192.168.1.20",
			format:  "tsv",
		},
		{
			name:    "Special characters",
			payload: "CEF:0|Vendor|Product|1.0|100|Test Event|5|msg=hello=world",
			format:  "cef",
		},
		{
			name:    "JSON-looking text",
			payload: `{"action":"BLOCK","src_ip":"10.0.0.1","nested":{"key":"value"}}`,
			format:  "json",
		},
		{
			name:    "XML-looking text",
			payload: "<Event><System><EventID>4624</EventID></System></Event>",
			format:  "xml",
		},
		{
			name:    "Trailing space",
			payload: "firewall01 DENY TCP ",
			format:  "syslog",
		},
		{
			name:    "Newline",
			payload: "line-one\nline-two",
			format:  "syslog",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			raw := models.RawEvent{
				EventID:    "evt_raw_test",
				ReceivedAt: "2026-08-28T18:30:12Z",
				Format:     tt.format,
				Source:     "test-source",
				Payload:    tt.payload,
			}

			parsed := &models.ParsedEvent{
				Timestamp: "2026-08-28T18:30:12Z",
				Source: models.SourceInfo{
					Identifier: "test-source",
				},
			}

			detectionRes := models.DetectionResult{
				Format:     tt.format,
				SourceType: "test",
				Confidence: 1.0,
			}

			universal, err := normalizer.Normalize(raw, parsed, detectionRes)
			if err != nil {
				t.Fatalf("unexpected normalization error: %v", err)
			}

			// Assert universal.Raw.Message == raw.Payload exactly
			if universal.Raw.Message != raw.Payload {
				t.Errorf("expected Raw.Message %q, got %q", raw.Payload, universal.Raw.Message)
			}

			// Assert universal.Raw.Format remains the expected format
			if universal.Raw.Format != tt.format {
				t.Errorf("expected Raw.Format %q, got %q", tt.format, universal.Raw.Format)
			}

			// Assert that the original RawEvent.Payload itself has not been modified
			if raw.Payload != tt.payload {
				t.Errorf("original RawEvent.Payload was modified: expected %q, got %q", tt.payload, raw.Payload)
			}
		})
	}
}

func TestNormalizer_TimestampHandling(t *testing.T) {
	normalizer := NewNormalizer()

	t.Run("ParsedEvent timestamp priority", func(t *testing.T) {
		parsedTs := "2026-08-28T18:30:12Z"
		receivedTs := "2026-08-28T18:35:00Z"

		raw := models.RawEvent{
			EventID:    "evt_ts_1",
			ReceivedAt: receivedTs,
			Payload:    "sample log",
		}
		parsed := &models.ParsedEvent{
			Timestamp: parsedTs,
		}
		detectionRes := models.DetectionResult{
			Format: "syslog",
		}

		universal, err := normalizer.Normalize(raw, parsed, detectionRes)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if universal.Timestamp != parsedTs {
			t.Errorf("expected timestamp %q, got %q", parsedTs, universal.Timestamp)
		}
	})

	t.Run("Fallback to RawEvent.ReceivedAt when ParsedEvent timestamp is empty", func(t *testing.T) {
		receivedTs := "2026-08-28T18:35:00Z"

		raw := models.RawEvent{
			EventID:    "evt_ts_2",
			ReceivedAt: receivedTs,
			Payload:    "sample log",
		}
		parsed := &models.ParsedEvent{
			Timestamp: "",
		}
		detectionRes := models.DetectionResult{
			Format: "syslog",
		}

		universal, err := normalizer.Normalize(raw, parsed, detectionRes)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if universal.Timestamp != receivedTs {
			t.Errorf("expected timestamp %q, got %q", receivedTs, universal.Timestamp)
		}
	})

	t.Run("Fallback to time.Now() when both parsed and raw timestamps are empty", func(t *testing.T) {
		before := time.Now().UTC().Add(-1 * time.Second)

		raw := models.RawEvent{
			EventID:    "evt_ts_3",
			ReceivedAt: "",
			Payload:    "sample log",
		}
		parsed := &models.ParsedEvent{
			Timestamp: "",
		}
		detectionRes := models.DetectionResult{
			Format: "syslog",
		}

		universal, err := normalizer.Normalize(raw, parsed, detectionRes)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if universal.Timestamp == "" {
			t.Fatal("expected non-empty timestamp fallback, got empty string")
		}

		parsedTime, err := time.Parse(time.RFC3339, universal.Timestamp)
		if err != nil {
			t.Fatalf("expected valid RFC3339 timestamp fallback, got error: %v", err)
		}

		after := time.Now().UTC().Add(1 * time.Second)
		if parsedTime.Before(before) || parsedTime.After(after) {
			t.Errorf("generated timestamp %v out of expected range [%v, %v]", parsedTime, before, after)
		}
	})

	t.Run("Provided timestamp is preserved without modification", func(t *testing.T) {
		customTs := "2026-08-28T18:30:12.123456Z"

		raw := models.RawEvent{
			EventID:    "evt_ts_4",
			ReceivedAt: "2026-08-28T18:00:00Z",
			Payload:    "sample log",
		}
		parsed := &models.ParsedEvent{
			Timestamp: customTs,
		}
		detectionRes := models.DetectionResult{
			Format: "syslog",
		}

		universal, err := normalizer.Normalize(raw, parsed, detectionRes)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if universal.Timestamp != customTs {
			t.Errorf("expected exact timestamp %q preserved, got %q", customTs, universal.Timestamp)
		}
	})
}

func TestNormalizer_OutputPassesValidation(t *testing.T) {
	normalizer := NewNormalizer()
	val, err := validation.NewValidator("")
	if err != nil {
		t.Fatalf("failed to initialize JSON schema validator: %v", err)
	}

	srcPort := 54321
	dstPort := 443

	raw := models.RawEvent{
		EventID:    "evt_integration_001",
		Format:     "syslog",
		Source:     "firewall-01",
		ReceivedAt: "2026-08-28T18:30:12Z",
		Payload:    "Aug 28 18:30:12 firewall01 DENY TCP SRC=192.168.1.20:54321 DST=10.0.0.15:443",
	}

	parsed := &models.ParsedEvent{
		Timestamp: "2026-08-28T18:30:12Z",
		Source: models.SourceInfo{
			Type:       "firewall",
			Vendor:     "Cisco",
			Product:    "ASA",
			Identifier: "firewall-01",
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
	}

	detectionRes := models.DetectionResult{
		Format:     "syslog",
		SourceType: "firewall",
		Confidence: 1.0,
	}

	universal, err := normalizer.Normalize(raw, parsed, detectionRes)
	if err != nil {
		t.Fatalf("unexpected normalization error: %v", err)
	}
	if universal == nil {
		t.Fatal("expected non-nil UniversalEvent")
	}

	res := val.Validate(universal)
	if !res.Valid {
		t.Fatalf("expected UniversalEvent to pass JSON schema validation, got errors: %+v", res.Errors)
	}
	if len(res.Errors) != 0 {
		t.Errorf("expected 0 validation errors, got %d", len(res.Errors))
	}

	if universal.EventID != "evt_integration_001" {
		t.Errorf("expected EventID 'evt_integration_001', got %q", universal.EventID)
	}
	if universal.SchemaVersion != "1.0" {
		t.Errorf("expected SchemaVersion '1.0', got %q", universal.SchemaVersion)
	}
	if universal.Raw.Message != raw.Payload {
		t.Errorf("expected Raw.Message %q, got %q", raw.Payload, universal.Raw.Message)
	}
}

func TestNormalizer_OptionalSections(t *testing.T) {
	normalizer := NewNormalizer()
	username := "alice"
	srcPort := 54321

	raw := models.RawEvent{
		EventID:    "evt_opt_001",
		Format:     "syslog",
		Source:     "syslog-server",
		ReceivedAt: "2026-08-28T18:30:12Z",
		Payload:    "Aug 28 18:30:12 syslog-server LOG_MESSAGE",
	}

	detectionRes := models.DetectionResult{
		Format:     "syslog",
		SourceType: "system",
		Confidence: 1.0,
	}

	t.Run("1. Network == nil and User == nil", func(t *testing.T) {
		parsed := &models.ParsedEvent{
			Timestamp: "2026-08-28T18:30:12Z",
			Source: models.SourceInfo{
				Type:       "system",
				Identifier: "syslog-server",
			},
			Event: models.EventInfo{
				Category: "system",
				Action:   "log",
			},
			Network: nil,
			User:    nil,
		}

		universal, err := normalizer.Normalize(raw, parsed, detectionRes)
		if err != nil {
			t.Fatalf("unexpected normalization error: %v", err)
		}
		if universal == nil {
			t.Fatal("expected non-nil UniversalEvent")
		}

		if universal.Network != nil {
			t.Errorf("expected Network to be nil, got %+v", universal.Network)
		}
		if universal.User != nil {
			t.Errorf("expected User to be nil, got %+v", universal.User)
		}

		if universal.EventID != raw.EventID {
			t.Errorf("expected EventID %q, got %q", raw.EventID, universal.EventID)
		}
		if universal.SchemaVersion != "1.0" {
			t.Errorf("expected SchemaVersion '1.0', got %q", universal.SchemaVersion)
		}
		if universal.Raw.Message != raw.Payload {
			t.Errorf("expected Raw.Message %q, got %q", raw.Payload, universal.Raw.Message)
		}
	})

	t.Run("2. Network populated and User == nil", func(t *testing.T) {
		parsed := &models.ParsedEvent{
			Timestamp: "2026-08-28T18:30:12Z",
			Source: models.SourceInfo{
				Type:       "system",
				Identifier: "syslog-server",
			},
			Event: models.EventInfo{
				Category: "network",
				Action:   "connect",
			},
			Network: &models.NetworkInfo{
				SrcIP:   "192.168.1.20",
				SrcPort: &srcPort,
			},
			User: nil,
		}

		universal, err := normalizer.Normalize(raw, parsed, detectionRes)
		if err != nil {
			t.Fatalf("unexpected normalization error: %v", err)
		}

		if universal.Network == nil || universal.Network.SrcIP != "192.168.1.20" {
			t.Errorf("expected Network.SrcIP '192.168.1.20', got %+v", universal.Network)
		}
		if universal.User != nil {
			t.Errorf("expected User to be nil, got %+v", universal.User)
		}

		if universal.EventID != raw.EventID {
			t.Errorf("expected EventID %q, got %q", raw.EventID, universal.EventID)
		}
		if universal.SchemaVersion != "1.0" {
			t.Errorf("expected SchemaVersion '1.0', got %q", universal.SchemaVersion)
		}
		if universal.Raw.Message != raw.Payload {
			t.Errorf("expected Raw.Message %q, got %q", raw.Payload, universal.Raw.Message)
		}
	})

	t.Run("3. User populated and Network == nil", func(t *testing.T) {
		parsed := &models.ParsedEvent{
			Timestamp: "2026-08-28T18:30:12Z",
			Source: models.SourceInfo{
				Type:       "system",
				Identifier: "syslog-server",
			},
			Event: models.EventInfo{
				Category: "auth",
				Action:   "login",
			},
			Network: nil,
			User: &models.UserInfo{
				Username: &username,
			},
		}

		universal, err := normalizer.Normalize(raw, parsed, detectionRes)
		if err != nil {
			t.Fatalf("unexpected normalization error: %v", err)
		}

		if universal.Network != nil {
			t.Errorf("expected Network to be nil, got %+v", universal.Network)
		}
		if universal.User == nil || universal.User.Username == nil || *universal.User.Username != "alice" {
			t.Errorf("expected User.Username 'alice', got %+v", universal.User)
		}

		if universal.EventID != raw.EventID {
			t.Errorf("expected EventID %q, got %q", raw.EventID, universal.EventID)
		}
		if universal.SchemaVersion != "1.0" {
			t.Errorf("expected SchemaVersion '1.0', got %q", universal.SchemaVersion)
		}
		if universal.Raw.Message != raw.Payload {
			t.Errorf("expected Raw.Message %q, got %q", raw.Payload, universal.Raw.Message)
		}
	})

	t.Run("4. Both Network and User populated", func(t *testing.T) {
		parsed := &models.ParsedEvent{
			Timestamp: "2026-08-28T18:30:12Z",
			Source: models.SourceInfo{
				Type:       "system",
				Identifier: "syslog-server",
			},
			Event: models.EventInfo{
				Category: "auth",
				Action:   "login",
			},
			Network: &models.NetworkInfo{
				SrcIP:   "192.168.1.20",
				SrcPort: &srcPort,
			},
			User: &models.UserInfo{
				Username: &username,
			},
		}

		universal, err := normalizer.Normalize(raw, parsed, detectionRes)
		if err != nil {
			t.Fatalf("unexpected normalization error: %v", err)
		}

		if universal.Network == nil || universal.Network.SrcIP != "192.168.1.20" {
			t.Errorf("expected Network data preserved, got %+v", universal.Network)
		}
		if universal.User == nil || universal.User.Username == nil || *universal.User.Username != "alice" {
			t.Errorf("expected User data preserved, got %+v", universal.User)
		}

		if universal.EventID != raw.EventID {
			t.Errorf("expected EventID %q, got %q", raw.EventID, universal.EventID)
		}
		if universal.SchemaVersion != "1.0" {
			t.Errorf("expected SchemaVersion '1.0', got %q", universal.SchemaVersion)
		}
		if universal.Raw.Message != raw.Payload {
			t.Errorf("expected Raw.Message %q, got %q", raw.Payload, universal.Raw.Message)
		}
	})
}

func TestNormalizer_MVPFormatsCoverage(t *testing.T) {
	normalizer := NewNormalizer()
	val, err := validation.NewValidator("")
	if err != nil {
		t.Fatalf("failed to initialize validator: %v", err)
	}

	srcPort := 54321
	dstPort := 443

	tests := []struct {
		name         string
		raw          models.RawEvent
		parsed       *models.ParsedEvent
		detectionRes models.DetectionResult
	}{
		{
			name: "Case 1: Syslog (Cisco ASA)",
			raw: models.RawEvent{
				EventID:    "evt_mvp_syslog_001",
				Format:     "syslog",
				Source:     "firewall-01",
				ReceivedAt: "2026-08-28T18:30:12Z",
				Payload:    "Aug 28 18:30:12 firewall01 DENY TCP SRC=192.168.1.20:54321 DST=10.0.0.15:443",
			},
			parsed: &models.ParsedEvent{
				Timestamp: "2026-08-28T18:30:12Z",
				Source: models.SourceInfo{
					Type:       "firewall",
					Vendor:     "Cisco",
					Product:    "ASA",
					Identifier: "firewall-01",
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
			},
			detectionRes: models.DetectionResult{
				Format:     "syslog",
				SourceType: "firewall",
				Confidence: 1.0,
			},
		},
		{
			name: "Case 2: JSON (Radware WAF)",
			raw: models.RawEvent{
				EventID:    "evt_mvp_json_001",
				Format:     "json",
				Source:     "waf-01",
				ReceivedAt: "2026-08-28T18:31:12Z",
				Payload:    `{"timestamp":"2026-08-28T18:31:12Z","firewall":{"action":"deny","protocol":"TCP"},"network":{"source":{"ip":"192.168.1.20","port":54321},"destination":{"ip":"10.0.0.15","port":443}}}`,
			},
			parsed: &models.ParsedEvent{
				Timestamp: "2026-08-28T18:31:12Z",
				Source: models.SourceInfo{
					Type:       "waf",
					Vendor:     "Radware",
					Product:    "AppWall",
					Identifier: "waf-01",
				},
				Event: models.EventInfo{
					Category: "security",
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
			},
			detectionRes: models.DetectionResult{
				Format:     "json",
				SourceType: "waf",
				Confidence: 1.0,
			},
		},
		{
			name: "Case 3: CSV (Network Monitor)",
			raw: models.RawEvent{
				EventID:    "evt_mvp_csv_001",
				Format:     "csv",
				Source:     "network-monitor",
				ReceivedAt: "2026-08-28T18:32:12Z",
				Payload:    "timestamp,action,protocol,src_ip,src_port,dst_ip,dst_port\n2026-08-28T18:32:12Z,deny,TCP,192.168.1.20,54321,10.0.0.15,443",
			},
			parsed: &models.ParsedEvent{
				Timestamp: "2026-08-28T18:32:12Z",
				Source: models.SourceInfo{
					Type:       "network",
					Vendor:     "Generic",
					Product:    "NetMon",
					Identifier: "network-monitor",
				},
				Event: models.EventInfo{
					Category: "network",
					Action:   "deny",
					Severity: "medium",
				},
				Network: &models.NetworkInfo{
					SrcIP:    "192.168.1.20",
					SrcPort:  &srcPort,
					DstIP:    "10.0.0.15",
					DstPort:  &dstPort,
					Protocol: "TCP",
				},
			},
			detectionRes: models.DetectionResult{
				Format:     "csv",
				SourceType: "network",
				Confidence: 1.0,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			universal, err := normalizer.Normalize(tt.raw, tt.parsed, tt.detectionRes)
			// 1. Normalize returns no error.
			if err != nil {
				t.Fatalf("unexpected normalization error: %v", err)
			}
			// 2. UniversalEvent is not nil.
			if universal == nil {
				t.Fatal("expected non-nil UniversalEvent")
			}

			// 3. EventID is preserved.
			if universal.EventID != tt.raw.EventID {
				t.Errorf("expected EventID %q, got %q", tt.raw.EventID, universal.EventID)
			}
			// 4. SchemaVersion is "1.0".
			if universal.SchemaVersion != "1.0" {
				t.Errorf("expected SchemaVersion '1.0', got %q", universal.SchemaVersion)
			}
			// 5. Timestamp is preserved from ParsedEvent.
			if universal.Timestamp != tt.parsed.Timestamp {
				t.Errorf("expected Timestamp %q, got %q", tt.parsed.Timestamp, universal.Timestamp)
			}
			// 6. Source is preserved.
			if universal.Source != tt.parsed.Source {
				t.Errorf("expected Source %+v, got %+v", tt.parsed.Source, universal.Source)
			}
			// 7. Event information is preserved.
			if universal.Event != tt.parsed.Event {
				t.Errorf("expected Event %+v, got %+v", tt.parsed.Event, universal.Event)
			}
			// 8. Network information is preserved when present.
			if universal.Network == nil || *universal.Network != *tt.parsed.Network {
				t.Errorf("expected Network %+v, got %+v", tt.parsed.Network, universal.Network)
			}
			// 9. Raw.Format is correct.
			if universal.Raw.Format != tt.raw.Format {
				t.Errorf("expected Raw.Format %q, got %q", tt.raw.Format, universal.Raw.Format)
			}
			// 10. Raw.Message is EXACTLY equal to RawEvent.Payload.
			if universal.Raw.Message != tt.raw.Payload {
				t.Errorf("expected Raw.Message %q, got %q", tt.raw.Payload, universal.Raw.Message)
			}

			// 11. Resulting UniversalEvent passes existing JSON Schema Validator.
			valRes := val.Validate(universal)
			// 12. ValidationResult.Valid == true.
			if !valRes.Valid {
				t.Fatalf("expected UniversalEvent to pass JSON Schema validation, got errors: %+v", valRes.Errors)
			}
			// 13. ValidationResult.Errors is empty.
			if len(valRes.Errors) != 0 {
				t.Errorf("expected 0 validation errors, got %d", len(valRes.Errors))
			}
		})
	}
}

func TestNormalizer_NilParsedEvent(t *testing.T) {
	normalizer := NewNormalizer()

	raw := models.RawEvent{
		EventID:    "evt_nil_parsed_001",
		Format:     "syslog",
		Source:     "firewall-01",
		ReceivedAt: "2026-08-28T18:30:12Z",
		Payload:    "Aug 28 18:30:12 firewall01 DENY TCP",
	}

	detectionRes := models.DetectionResult{
		Format:     "syslog",
		SourceType: "firewall",
		Confidence: 1.0,
	}

	universal, err := normalizer.Normalize(raw, nil, detectionRes)
	if err == nil {
		t.Fatal("expected error when passing nil ParsedEvent, got nil error")
	}
	if universal != nil {
		t.Errorf("expected nil UniversalEvent when ParsedEvent is nil, got %+v", universal)
	}

	expectedErrSubstr := "nil parsed event"
	if !strings.Contains(err.Error(), expectedErrSubstr) {
		t.Errorf("expected error message containing %q, got %q", expectedErrSubstr, err.Error())
	}
}
