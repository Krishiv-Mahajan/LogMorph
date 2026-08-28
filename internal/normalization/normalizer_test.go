package normalization

import (
	"testing"

	"github.com/Krishiv-Mahajan/LogMorph/internal/detection"
	"github.com/Krishiv-Mahajan/LogMorph/internal/models"
	"github.com/Krishiv-Mahajan/LogMorph/internal/normalization/parsers"
)

func setupTestNormalizer() *Normalizer {
	detector := detection.NewDetector()
	registry := NewRegistry()
	registry.Register(parsers.NewSyslogParser())
	registry.Register(parsers.NewJSONParser())
	registry.Register(parsers.NewCSVParser())
	return NewNormalizer(detector, registry)
}

func TestNormalizer_AllFormats(t *testing.T) {
	norm := setupTestNormalizer()

	tests := []struct {
		name        string
		raw         models.RawEvent
		expectedFmt string
		expectedAct string
	}{
		{
			name: "Syslog normalization",
			raw: models.RawEvent{
				Payload: "Aug 28 18:30:12 firewall01 DENY TCP SRC=192.168.1.20:54321 DST=10.0.0.15:443",
			},
			expectedFmt: "syslog",
			expectedAct: "deny",
		},
		{
			name: "JSON normalization",
			raw: models.RawEvent{
				Payload: `{"timestamp":"2026-08-28T18:30:12Z","firewall":{"action":"deny","protocol":"TCP"},"network":{"source":{"ip":"192.168.1.20","port":54321},"destination":{"ip":"10.0.0.15","port":443}}}`,
			},
			expectedFmt: "json",
			expectedAct: "deny",
		},
		{
			name: "CSV normalization",
			raw: models.RawEvent{
				Payload: "timestamp,action,protocol,src_ip,src_port,dst_ip,dst_port\n2026-08-28T18:30:12Z,deny,TCP,192.168.1.20,54321,10.0.0.15,443",
			},
			expectedFmt: "csv",
			expectedAct: "deny",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			event, err := norm.Normalize(tt.raw)
			if err != nil {
				t.Fatalf("Normalize failed: %v", err)
			}

			if event.EventID == "" {
				t.Error("expected non-empty EventID")
			}
			if event.SchemaVersion != "1.0" {
				t.Errorf("expected schema_version '1.0', got %q", event.SchemaVersion)
			}
			if event.Raw.Format != tt.expectedFmt {
				t.Errorf("expected raw format %q, got %q", tt.expectedFmt, event.Raw.Format)
			}
			if event.Event.Action != tt.expectedAct {
				t.Errorf("expected action %q, got %q", tt.expectedAct, event.Event.Action)
			}
			if event.Network == nil || event.Network.SrcIP != "192.168.1.20" {
				t.Errorf("expected src_ip '192.168.1.20', got %+v", event.Network)
			}
		})
	}
}
