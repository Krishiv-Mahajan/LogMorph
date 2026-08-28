package detection

import (
	"context"
	"testing"

	"github.com/Krishiv-Mahajan/LogMorph/internal/models"
)

func TestDefaultDriftDetector(t *testing.T) {
	driftDetector := NewDriftDetector()
	ctx := context.Background()

	t.Run("Stable format", func(t *testing.T) {
		detectionRes := models.DetectionResult{
			Format:     FormatSyslog,
			Confidence: 0.85,
		}
		raw := models.RawEvent{Payload: "Aug 28 18:30:12 firewall01 DENY TCP SRC=192.168.1.20:54321 DST=10.0.0.15:443"}

		result, err := driftDetector.Analyze(ctx, raw, detectionRes)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result.Status != models.DriftStatusStable {
			t.Errorf("expected status 'stable', got %q", result.Status)
		}
	})

	t.Run("Unknown format", func(t *testing.T) {
		detectionRes := models.DetectionResult{
			Format:     FormatUnknown,
			Confidence: 0.0,
		}
		raw := models.RawEvent{Payload: "unstructured noise"}

		result, err := driftDetector.Analyze(ctx, raw, detectionRes)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result.Status != models.DriftStatusUnknown {
			t.Errorf("expected status 'unknown', got %q", result.Status)
		}
	})
}
