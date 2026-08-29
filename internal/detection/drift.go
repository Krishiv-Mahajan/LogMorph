package detection

import (
	"context"
	"strings"

	"github.com/Krishiv-Mahajan/LogMorph/internal/models"
)

// DriftDetector evaluates whether an incoming event conforms to known schema expectations.
type DriftDetector interface {
	Analyze(ctx context.Context, event models.RawEvent, detection models.DetectionResult) (models.DriftResult, error)
}

// DefaultDriftDetector provides a deterministic MVP implementation of drift analysis.
type DefaultDriftDetector struct{}

// NewDriftDetector initializes the default drift detector.
func NewDriftDetector() *DefaultDriftDetector {
	return &DefaultDriftDetector{}
}

// Analyze performs deterministic drift check.
// Known formats (syslog, json, csv) with confidence >= 0.5 are classified as STABLE.
// Unrecognized formats, empty formats, or low-confidence inputs are classified as UNKNOWN (candidate for future AI escalation).
func (d *DefaultDriftDetector) Analyze(ctx context.Context, event models.RawEvent, detection models.DetectionResult) (models.DriftResult, error) {
	if err := ctx.Err(); err != nil {
		return models.DriftResult{}, err
	}

	format := strings.ToLower(strings.TrimSpace(detection.Format))
	if (format != FormatSyslog && format != FormatJSON && format != FormatCSV) || detection.Confidence < 0.5 {
		return models.DriftResult{
			Status:          models.DriftStatusUnknown,
			Confidence:      detection.Confidence,
			Message:         "Unrecognized log schema structure; candidate for AI escalation",
			SuggestedAction: "escalate_to_ai",
		}, nil
	}

	return models.DriftResult{
		Status:          models.DriftStatusStable,
		Confidence:      detection.Confidence,
		Message:         "Payload matches established " + format + " parser contract",
		SuggestedAction: "route_to_parser",
	}, nil
}
