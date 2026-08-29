package detection

import (
	"context"
	"testing"

	"github.com/Krishiv-Mahajan/LogMorph/internal/models"
)

func TestDefaultDriftDetector_Comprehensive(t *testing.T) {
	driftDetector := NewDriftDetector()
	ctx := context.Background()

	tests := []struct {
		name           string
		format         string
		confidence     float64
		payload        string
		expectedStatus models.DriftStatus
		expectedAction string
	}{
		// 1. Stable Cases
		{
			name:           "Syslog + confidence 0.95 -> stable",
			format:         FormatSyslog,
			confidence:     0.95,
			payload:        "Aug 28 18:30:12 firewall01 DENY TCP SRC=192.168.1.20:54321 DST=10.0.0.15:443",
			expectedStatus: models.DriftStatusStable,
			expectedAction: "route_to_parser",
		},
		{
			name:           "JSON + confidence 0.95 -> stable",
			format:         FormatJSON,
			confidence:     0.95,
			payload:        `{"timestamp":"2026-08-28T18:30:12Z","action":"deny"}`,
			expectedStatus: models.DriftStatusStable,
			expectedAction: "route_to_parser",
		},
		{
			name:           "CSV + confidence 0.90 -> stable",
			format:         FormatCSV,
			confidence:     0.90,
			payload:        "timestamp,action,protocol\n2026-08-28T18:30:12Z,deny,TCP",
			expectedStatus: models.DriftStatusStable,
			expectedAction: "route_to_parser",
		},
		{
			name:           "Case-insensitive format JSON with whitespace -> stable",
			format:         "  JSON  ",
			confidence:     0.85,
			payload:        `{"test": true}`,
			expectedStatus: models.DriftStatusStable,
			expectedAction: "route_to_parser",
		},

		// 2. Unknown Cases
		{
			name:           "Unknown format + confidence 0.0 -> unknown",
			format:         FormatUnknown,
			confidence:     0.0,
			payload:        "unstructured noise",
			expectedStatus: models.DriftStatusUnknown,
			expectedAction: "escalate_to_ai",
		},
		{
			name:           "Empty format -> unknown",
			format:         "",
			confidence:     0.0,
			payload:        "some payload",
			expectedStatus: models.DriftStatusUnknown,
			expectedAction: "escalate_to_ai",
		},
		{
			name:           "Whitespace format -> unknown",
			format:         "   ",
			confidence:     0.8,
			payload:        "some payload",
			expectedStatus: models.DriftStatusUnknown,
			expectedAction: "escalate_to_ai",
		},
		{
			name:           "JSON + confidence 0.49 (below threshold) -> unknown",
			format:         FormatJSON,
			confidence:     0.49,
			payload:        `{"incomplete": true}`,
			expectedStatus: models.DriftStatusUnknown,
			expectedAction: "escalate_to_ai",
		},
		{
			name:           "Syslog + confidence 0.30 (low confidence) -> unknown",
			format:         FormatSyslog,
			confidence:     0.30,
			payload:        "random text with Aug",
			expectedStatus: models.DriftStatusUnknown,
			expectedAction: "escalate_to_ai",
		},
		{
			name:           "Unrecognized format (XML) with high confidence -> unknown",
			format:         "xml",
			confidence:     0.95,
			payload:        "<log><action>deny</action></log>",
			expectedStatus: models.DriftStatusUnknown,
			expectedAction: "escalate_to_ai",
		},

		// 3. Boundary Cases
		{
			name:           "JSON + confidence 0.50 (exact threshold) -> stable",
			format:         FormatJSON,
			confidence:     0.50,
			payload:        `{"action":"deny"}`,
			expectedStatus: models.DriftStatusStable,
			expectedAction: "route_to_parser",
		},
		{
			name:           "JSON + confidence 0.51 (just above threshold) -> stable",
			format:         FormatJSON,
			confidence:     0.51,
			payload:        `{"action":"deny"}`,
			expectedStatus: models.DriftStatusStable,
			expectedAction: "route_to_parser",
		},
		{
			name:           "Syslog + confidence 0.4999 (just below threshold) -> unknown",
			format:         FormatSyslog,
			confidence:     0.4999,
			payload:        "Aug 28 18:30:12 test",
			expectedStatus: models.DriftStatusUnknown,
			expectedAction: "escalate_to_ai",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			detectionRes := models.DetectionResult{
				Format:     tt.format,
				Confidence: tt.confidence,
			}
			raw := models.RawEvent{Payload: tt.payload}

			result, err := driftDetector.Analyze(ctx, raw, detectionRes)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if result.Status != tt.expectedStatus {
				t.Errorf("expected status %q, got %q", tt.expectedStatus, result.Status)
			}
			if result.SuggestedAction != tt.expectedAction {
				t.Errorf("expected suggested action %q, got %q", tt.expectedAction, result.SuggestedAction)
			}
			if result.Confidence != tt.confidence {
				t.Errorf("expected confidence %f, got %f", tt.confidence, result.Confidence)
			}
		})
	}
}

func TestDefaultDriftDetector_ContextCancellation(t *testing.T) {
	driftDetector := NewDriftDetector()
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	detectionRes := models.DetectionResult{
		Format:     FormatSyslog,
		Confidence: 0.95,
	}
	raw := models.RawEvent{Payload: "test"}

	_, err := driftDetector.Analyze(ctx, raw, detectionRes)
	if err == nil {
		t.Errorf("expected context error on cancelled context, got nil")
	}
}

func TestDriftStatusEnum_DeclaredConstants(t *testing.T) {
	// Verify that all declared enum contract constants exist and have expected string representations
	if models.DriftStatusStable != "stable" {
		t.Errorf("expected DriftStatusStable to be 'stable', got %q", models.DriftStatusStable)
	}
	if models.DriftStatusMinorDrift != "minor_drift" {
		t.Errorf("expected DriftStatusMinorDrift to be 'minor_drift', got %q", models.DriftStatusMinorDrift)
	}
	if models.DriftStatusMajorDrift != "major_drift" {
		t.Errorf("expected DriftStatusMajorDrift to be 'major_drift', got %q", models.DriftStatusMajorDrift)
	}
	if models.DriftStatusUnknown != "unknown" {
		t.Errorf("expected DriftStatusUnknown to be 'unknown', got %q", models.DriftStatusUnknown)
	}
}

