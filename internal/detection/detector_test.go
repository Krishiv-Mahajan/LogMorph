package detection

import (
	"testing"
)

func TestDefaultDetector_AllScenarios(t *testing.T) {
	detector := NewDetector()

	tests := []struct {
		name           string
		payload        string
		hint           string
		expectedFormat string
		expectedSource string
		minConfidence  float64
		maxConfidence  float64
	}{
		// 1. Explicit format hints (with casing and surrounding whitespace)
		{
			name:           "Explicit hint: syslog exact",
			payload:        "random unparsed content",
			hint:           "syslog",
			expectedFormat: FormatSyslog,
			expectedSource: "firewall",
			minConfidence:  1.0,
			maxConfidence:  1.0,
		},
		{
			name:           "Explicit hint: SYSLOG with whitespace",
			payload:        "random unparsed content",
			hint:           "  SYSLOG  ",
			expectedFormat: FormatSyslog,
			expectedSource: "firewall",
			minConfidence:  1.0,
			maxConfidence:  1.0,
		},
		{
			name:           "Explicit hint: JSON upper",
			payload:        "random unparsed content",
			hint:           "JSON",
			expectedFormat: FormatJSON,
			expectedSource: "firewall",
			minConfidence:  1.0,
			maxConfidence:  1.0,
		},
		{
			name:           "Explicit hint: CSV mixed case with whitespace",
			payload:        "random unparsed content",
			hint:           "  Csv  ",
			expectedFormat: FormatCSV,
			expectedSource: "firewall",
			minConfidence:  1.0,
			maxConfidence:  1.0,
		},

		// 2. Unsupported hint fallback
		{
			name:           "Unsupported hint xml with plain text payload falls back to unknown",
			payload:        "just some random text line",
			hint:           "xml",
			expectedFormat: FormatUnknown,
			expectedSource: "unknown",
			minConfidence:  0.0,
			maxConfidence:  0.0,
		},
		{
			name:           "Unsupported hint xml with valid JSON payload falls back to auto-detecting JSON",
			payload:        `{"action": "block", "src_ip": "192.168.1.1"}`,
			hint:           "xml",
			expectedFormat: FormatJSON,
			expectedSource: "firewall",
			minConfidence:  0.90,
			maxConfidence:  1.0,
		},

		// 3. Automatic detection — Syslog
		{
			name:           "Syslog standard BSD sample",
			payload:        "Aug 28 18:30:12 firewall01 DENY TCP SRC=192.168.1.20:54321 DST=10.0.0.15:443",
			hint:           "",
			expectedFormat: FormatSyslog,
			expectedSource: "firewall",
			minConfidence:  0.80,
			maxConfidence:  0.95,
		},
		{
			name:           "Syslog with RFC5424 priority prefix",
			payload:        "<134>Aug 28 18:30:12 host01 ALLOW UDP SRC=10.0.0.1:53 DST=10.0.0.2:53",
			hint:           "",
			expectedFormat: FormatSyslog,
			expectedSource: "firewall",
			minConfidence:  0.80,
			maxConfidence:  0.95,
		},

		// 4. Automatic detection — JSON
		{
			name: "JSON flat MVP sample",
			payload: `{
				"timestamp": "2026-08-29T10:15:00Z",
				"action": "block",
				"src_ip": "192.168.1.50",
				"src_port": 45678,
				"dst_ip": "10.0.0.20",
				"dst_port": 443,
				"protocol": "TCP"
			}`,
			hint:           "",
			expectedFormat: FormatJSON,
			expectedSource: "firewall",
			minConfidence:  0.90,
			maxConfidence:  1.0,
		},
		{
			name: "JSON nested firewall sample",
			payload: `{
				"timestamp": "2026-08-28T18:30:12Z",
				"firewall": {"action": "deny", "protocol": "TCP"},
				"network": {"src_ip": "192.168.1.20", "dst_ip": "10.0.0.15"}
			}`,
			hint:           "",
			expectedFormat: FormatJSON,
			expectedSource: "firewall",
			minConfidence:  0.90,
			maxConfidence:  1.0,
		},

		// 5. Automatic detection — CSV
		{
			name:           "CSV standard MVP sample",
			payload:        "timestamp,action,protocol,src_ip,src_port,dst_ip,dst_port\n2026-08-28T18:30:12Z,deny,TCP,192.168.1.20,54321,10.0.0.15,443",
			hint:           "",
			expectedFormat: FormatCSV,
			expectedSource: "firewall",
			minConfidence:  0.85,
			maxConfidence:  0.95,
		},

		// 6. CSV False Positive Protection (Audit task)
		{
			name:           "Multiline text containing commas but not CSV headers",
			payload:        "Hello, this is line one.\nGoodbye, this is line two.",
			hint:           "",
			expectedFormat: FormatUnknown,
			expectedSource: "unknown",
			minConfidence:  0.0,
			maxConfidence:  0.0,
		},
		{
			name:           "Log traceback with commas",
			payload:        "error occurred at module A, code 404\nretrying connection, attempt 2",
			hint:           "",
			expectedFormat: FormatUnknown,
			expectedSource: "unknown",
			minConfidence:  0.0,
			maxConfidence:  0.0,
		},

		// 7. Unknown payloads
		{
			name:           "Empty payload",
			payload:        "",
			hint:           "",
			expectedFormat: FormatUnknown,
			expectedSource: "unknown",
			minConfidence:  0.0,
			maxConfidence:  0.0,
		},
		{
			name:           "Whitespace only payload",
			payload:        "   \n\t  ",
			hint:           "",
			expectedFormat: FormatUnknown,
			expectedSource: "unknown",
			minConfidence:  0.0,
			maxConfidence:  0.0,
		},
		{
			name:           "Unstructured plain text",
			payload:        "system reboot initiated by root",
			hint:           "",
			expectedFormat: FormatUnknown,
			expectedSource: "unknown",
			minConfidence:  0.0,
			maxConfidence:  0.0,
		},
		{
			name:           "XML format payload",
			payload:        "<event><timestamp>2026-08-29</timestamp><action>deny</action></event>",
			hint:           "",
			expectedFormat: FormatUnknown,
			expectedSource: "unknown",
			minConfidence:  0.0,
			maxConfidence:  0.0,
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
			if res.Confidence < tt.minConfidence || res.Confidence > tt.maxConfidence {
				t.Errorf("expected confidence in [%.2f, %.2f], got %.2f", tt.minConfidence, tt.maxConfidence, res.Confidence)
			}
			if len(res.Reason) == 0 {
				t.Error("expected non-empty reason in DetectionResult")
			}
		})
	}
}
