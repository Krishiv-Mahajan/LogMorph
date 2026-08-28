package raw

import (
	"context"
	"testing"
	"time"

	"github.com/Krishiv-Mahajan/LogMorph/internal/models"
)

func TestMemoryRawStore(t *testing.T) {
	store := NewMemoryRawStore()
	ctx := context.Background()

	event := &models.RawEvent{
		EventID:    "evt_test_1",
		ReceivedAt: time.Now().UTC().Format(time.RFC3339),
		Format:     "syslog",
		Source:     "firewall-01",
		Payload:    "Aug 28 18:30:12 firewall01 DENY TCP SRC=192.168.1.20:54321 DST=10.0.0.15:443",
	}

	err := store.Put(ctx, event)
	if err != nil {
		t.Fatalf("unexpected error putting event: %v", err)
	}

	retrieved, err := store.Get(ctx, "evt_test_1")
	if err != nil {
		t.Fatalf("unexpected error getting event: %v", err)
	}

	if retrieved.EventID != event.EventID {
		t.Errorf("expected EventID %q, got %q", event.EventID, retrieved.EventID)
	}
	if retrieved.Payload != event.Payload {
		t.Errorf("expected Payload %q, got %q", event.Payload, retrieved.Payload)
	}
}
