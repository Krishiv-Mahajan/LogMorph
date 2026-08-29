package detection

import (
	"bytes"
	"encoding/csv"
	"encoding/json"
	"regexp"
	"strings"

	"github.com/Krishiv-Mahajan/LogMorph/internal/models"
)

// Format constants
const (
	FormatSyslog  = "syslog"
	FormatJSON    = "json"
	FormatCSV     = "csv"
	FormatUnknown = "unknown"
)

var (
	// Matches standard BSD syslog timestamp (e.g., "Aug 28 18:30:12", "<134>Aug 28 18:30:12") or ISO8601 prefix
	syslogTimestampRegex = regexp.MustCompile(`^(?:<\d+>)?(?:[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2}|\d{4}-\d{2}-\d{2}[T\s]\d{2}:\d{2}:\d{2})`)
	// Matches standard firewall key-value pairs
	syslogKVRegex = regexp.MustCompile(`(?i)\b(?:SRC|DST|SPT|DPT|PROTO|ACTION)=`)
)

// Detector defines the interface for detecting log formats and source types.
type Detector interface {
	Detect(payload string, hint string) models.DetectionResult
}

// DefaultDetector implements deterministic format and source detection.
type DefaultDetector struct{}

// NewDetector returns a new DefaultDetector.
func NewDetector() *DefaultDetector {
	return &DefaultDetector{}
}

// Detect analyzes the payload and optional format hint to determine structure and source.
func (d *DefaultDetector) Detect(payload string, hint string) models.DetectionResult {
	cleanedHint := strings.ToLower(strings.TrimSpace(hint))
	switch cleanedHint {
	case FormatSyslog:
		return models.DetectionResult{
			Format:     FormatSyslog,
			SourceType: "firewall",
			Confidence: 1.0,
			Reason:     "Format explicitly provided by caller as syslog",
		}
	case FormatJSON:
		return models.DetectionResult{
			Format:     FormatJSON,
			SourceType: "firewall",
			Confidence: 1.0,
			Reason:     "Format explicitly provided by caller as json",
		}
	case FormatCSV:
		return models.DetectionResult{
			Format:     FormatCSV,
			SourceType: "firewall",
			Confidence: 1.0,
			Reason:     "Format explicitly provided by caller as csv",
		}
	}

	trimmed := strings.TrimSpace(payload)
	if trimmed == "" {
		return models.DetectionResult{
			Format:     FormatUnknown,
			SourceType: "unknown",
			Confidence: 0.0,
			Reason:     "Payload is empty",
		}
	}

	// 1. JSON Detection
	if (strings.HasPrefix(trimmed, "{") && strings.HasSuffix(trimmed, "}")) ||
		(strings.HasPrefix(trimmed, "[") && strings.HasSuffix(trimmed, "]")) {
		if json.Valid([]byte(trimmed)) {
			return models.DetectionResult{
				Format:     FormatJSON,
				SourceType: "firewall",
				Confidence: 0.95,
				Reason:     "Valid JSON structure detected",
			}
		}
	}

	// 2. CSV Detection
	// Requires comma delimiter, at least 2 rows (header + data), uniform columns (>=2), and recognizable header names.
	if strings.Contains(trimmed, ",") {
		reader := csv.NewReader(bytes.NewBufferString(trimmed))
		reader.TrimLeadingSpace = true
		records, err := reader.ReadAll()
		if err == nil && len(records) >= 2 && len(records[0]) >= 2 && len(records[0]) == len(records[1]) {
			hasHeaderSignals := false
			for _, col := range records[0] {
				c := strings.ToLower(strings.TrimSpace(col))
				if c == "timestamp" || c == "time" || c == "action" || c == "act" ||
					c == "protocol" || c == "proto" || c == "src_ip" || c == "dst_ip" ||
					c == "src_port" || c == "dst_port" || c == "source" || c == "severity" ||
					c == "ip" {
					hasHeaderSignals = true
					break
				}
			}
			if hasHeaderSignals {
				return models.DetectionResult{
					Format:     FormatCSV,
					SourceType: "firewall",
					Confidence: 0.90,
					Reason:     "CSV column structure with recognized headers detected",
				}
			}
		}
	}

	// 3. Syslog Detection
	// Requires standard timestamp prefix or security KV pairs (e.g. SRC=, DST=, ACTION=)
	if syslogTimestampRegex.MatchString(trimmed) || syslogKVRegex.MatchString(trimmed) {
		return models.DetectionResult{
			Format:     FormatSyslog,
			SourceType: "firewall",
			Confidence: 0.85,
			Reason:     "Syslog timestamp or key-value pattern detected",
		}
	}

	return models.DetectionResult{
		Format:     FormatUnknown,
		SourceType: "unknown",
		Confidence: 0.0,
		Reason:     "Unable to deterministically match syslog, json, or csv structure",
	}
}
