package normalization

import (
	"context"
	"testing"
	"time"

	"github.com/Krishiv-Mahajan/LogMorph/internal/models"
	"github.com/Krishiv-Mahajan/LogMorph/internal/parsing/parsers"
)

func TestNormalizer(t *testing.T) {
	normalizer := NewNormalizer()
	syslogParser := parsers.NewSyslogParser()
	ctx := context.Background()

	raw := models.RawEvent{
		EventID:    "evt_norm_123",
		ReceivedAt: time.Now().UTC().Format(time.RFC3339),
		Format:     "syslog",
		Source:     "firewall-01",
		Payload:    "Aug 28 18:30:12 firewall01 DENY TCP SRC=192.168.1.20:54321 DST=10.0.0.15:443",
	}

	parsed, err := syslogParser.Parse(ctx, raw)
	if err != nil {
		t.Fatalf("parser error: %v", err)
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

	if universal.EventID != "evt_norm_123" {
		t.Errorf("expected EventID 'evt_norm_123', got %q", universal.EventID)
	}
	if universal.SchemaVersion != "1.0" {
		t.Errorf("expected SchemaVersion '1.0', got %q", universal.SchemaVersion)
	}
	if universal.Raw.Format != "syslog" {
		t.Errorf("expected Raw.Format 'syslog', got %q", universal.Raw.Format)
	}
	if universal.Raw.Message != raw.Payload {
		t.Errorf("expected Raw.Message %q, got %q", raw.Payload, universal.Raw.Message)
	}
	if universal.Network.SrcIP != "192.168.1.20" {
		t.Errorf("expected SrcIP '192.168.1.20', got %q", universal.Network.SrcIP)
	}
}
