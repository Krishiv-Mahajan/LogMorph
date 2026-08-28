package detection

import (
	"testing"
)

func TestDefaultDetector(t *testing.T) {
	detector := NewDetector()

	tests := []struct {
		name           string
		payload        string
		hint           string
		expectedFormat string
		expectedSource string
	}{
		{
			name:           "Explicit hint overrides",
			payload:        "some unstructured string",
			hint:           "json",
			expectedFormat: FormatJSON,
			expectedSource: "firewall",
		},
		{
			name:           "JSON detection",
			payload:        `{"timestamp": "2026-08-28T18:30:12Z", "action": "deny"}`,
			hint:           "",
			expectedFormat: FormatJSON,
			expectedSource: "firewall",
		},
		{
			name:           "Syslog detection standard",
			payload:        "Aug 28 18:30:12 firewall01 DENY TCP SRC=192.168.1.20:54321 DST=10.0.0.15:443",
			hint:           "",
			expectedFormat: FormatSyslog,
			expectedSource: "firewall",
		},
		{
			name:           "CSV detection",
			payload:        "timestamp,action,protocol,src_ip,src_port,dst_ip,dst_port\n2026-08-28T18:30:12Z,deny,TCP,192.168.1.20,54321,10.0.0.15,443",
			hint:           "",
			expectedFormat: FormatCSV,
			expectedSource: "firewall",
		},
		{
			name:           "Unknown detection",
			payload:        "random noise without structure",
			hint:           "",
			expectedFormat: FormatUnknown,
			expectedSource: "unknown",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			res := detector.Detect(tt.payload, tt.hint)
			if res.Format != tt.expectedFormat {
				t.Fatalf("expected format %q, got %q (reason: %s)", tt.expectedFormat, res.Format, res.Reason)
			}
			if res.SourceType != tt.expectedSource {
				t.Errorf("expected source type %q, got %q", tt.expectedSource, res.SourceType)
			}
		})
	}
}
