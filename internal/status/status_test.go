package status_test

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"

	"github.com/Krishiv-Mahajan/LogMorph/internal/models"
	"github.com/Krishiv-Mahajan/LogMorph/internal/status"
)

// ── Helpers ───────────────────────────────────────────────────────────────────

func newStore() status.Store {
	return status.NewMemoryStatusStore()
}

func sampleStatus(eventID string) *status.EventStatus {
	return status.NewInitialStatus(eventID)
}

// ── Create + Get ──────────────────────────────────────────────────────────────

func TestMemoryStore_CreateAndGet(t *testing.T) {
	store := newStore()
	ctx := context.Background()

	s := sampleStatus("evt_001")
	if err := store.Create(ctx, s); err != nil {
		t.Fatalf("Create failed: %v", err)
	}

	got, err := store.Get(ctx, "evt_001")
	if err != nil {
		t.Fatalf("Get failed: %v", err)
	}
	if got.EventID != "evt_001" {
		t.Errorf("expected event_id evt_001, got %s", got.EventID)
	}
	if got.Status != status.StatusProcessing {
		t.Errorf("expected status Processing, got %s", got.Status)
	}
	// Ingestion stage must be success
	ingestion, ok := got.Stages[status.StageIngestion]
	if !ok {
		t.Fatal("expected ingestion stage to be present")
	}
	if ingestion.State != status.StateSuccess {
		t.Errorf("expected ingestion state success, got %s", ingestion.State)
	}
	// All other stages must be idle
	for _, name := range []string{
		status.StageDetection,
		status.StageDrift,
		status.StageParsing,
		status.StageNormalization,
		status.StageValidation,
	} {
		stage, ok := got.Stages[name]
		if !ok {
			t.Errorf("expected stage %s to be present", name)
			continue
		}
		if stage.State != status.StateIdle {
			t.Errorf("expected stage %s to be idle, got %s", name, stage.State)
		}
	}
}

// ── Not Found ─────────────────────────────────────────────────────────────────

func TestMemoryStore_GetMissing_ReturnsErrNotFound(t *testing.T) {
	store := newStore()
	_, err := store.Get(context.Background(), "does_not_exist")
	if !errors.Is(err, status.ErrNotFound) {
		t.Errorf("expected ErrNotFound, got %v", err)
	}
}

func TestMemoryStore_UpdateStageMissing_ReturnsErrNotFound(t *testing.T) {
	store := newStore()
	err := store.UpdateStage(context.Background(), "missing", status.StageResult{
		ID: status.StageDetection, State: status.StateSuccess,
	})
	if !errors.Is(err, status.ErrNotFound) {
		t.Errorf("expected ErrNotFound, got %v", err)
	}
}

func TestMemoryStore_UpdateOverallMissing_ReturnsErrNotFound(t *testing.T) {
	store := newStore()
	err := store.UpdateOverall(context.Background(), "missing", status.OverallUpdate{
		Status: status.StatusParsed,
	})
	if !errors.Is(err, status.ErrNotFound) {
		t.Errorf("expected ErrNotFound, got %v", err)
	}
}

// ── UpdateStage preserves other stages ───────────────────────────────────────

func TestMemoryStore_UpdateStage_PreservesOtherStages(t *testing.T) {
	store := newStore()
	ctx := context.Background()

	if err := store.Create(ctx, sampleStatus("evt_002")); err != nil {
		t.Fatal(err)
	}

	// Update detection to success
	if err := store.UpdateStage(ctx, "evt_002", status.StageResult{
		ID:     status.StageDetection,
		Label:  "Detection",
		State:  status.StateSuccess,
		Detail: "syslog • 85%",
	}); err != nil {
		t.Fatalf("UpdateStage failed: %v", err)
	}

	got, _ := store.Get(ctx, "evt_002")

	// Detection must be success
	if got.Stages[status.StageDetection].State != status.StateSuccess {
		t.Errorf("expected detection success")
	}
	// Ingestion must still be success (unchanged)
	if got.Stages[status.StageIngestion].State != status.StateSuccess {
		t.Errorf("expected ingestion still success, got %s", got.Stages[status.StageIngestion].State)
	}
	// Drift must still be idle (unchanged)
	if got.Stages[status.StageDrift].State != status.StateIdle {
		t.Errorf("expected drift still idle, got %s", got.Stages[status.StageDrift].State)
	}
}

// ── UpdateOverall preserves stages ───────────────────────────────────────────

func TestMemoryStore_UpdateOverall_PreservesStages(t *testing.T) {
	store := newStore()
	ctx := context.Background()

	if err := store.Create(ctx, sampleStatus("evt_003")); err != nil {
		t.Fatal(err)
	}

	if err := store.UpdateOverall(ctx, "evt_003", status.OverallUpdate{
		Status:          status.StatusParsed,
		FormatName:      "syslog",
		ConfidenceScore: 0.85,
	}); err != nil {
		t.Fatalf("UpdateOverall failed: %v", err)
	}

	got, _ := store.Get(ctx, "evt_003")
	if got.Status != status.StatusParsed {
		t.Errorf("expected status Parsed, got %s", got.Status)
	}
	if got.FormatName != "syslog" {
		t.Errorf("expected format_name syslog, got %s", got.FormatName)
	}
	// Stages must be untouched
	if len(got.Stages) != 6 {
		t.Errorf("expected 6 stages, got %d", len(got.Stages))
	}
}

// ── UpdateOverall with UniversalEvent ────────────────────────────────────────

func TestMemoryStore_UpdateOverall_StoresUniversalEvent(t *testing.T) {
	store := newStore()
	ctx := context.Background()

	if err := store.Create(ctx, sampleStatus("evt_004")); err != nil {
		t.Fatal(err)
	}

	ue := &models.UniversalEvent{
		EventID:       "evt_004",
		SchemaVersion: "1.0",
	}
	if err := store.UpdateOverall(ctx, "evt_004", status.OverallUpdate{
		Status:         status.StatusParsed,
		UniversalEvent: ue,
	}); err != nil {
		t.Fatal(err)
	}

	got, _ := store.Get(ctx, "evt_004")
	if got.UniversalEvent == nil {
		t.Fatal("expected UniversalEvent to be set")
	}
	if got.UniversalEvent.EventID != "evt_004" {
		t.Errorf("UniversalEvent.EventID mismatch: %s", got.UniversalEvent.EventID)
	}
}

// ── Delete ────────────────────────────────────────────────────────────────────

func TestMemoryStore_Delete(t *testing.T) {
	store := newStore()
	ctx := context.Background()

	if err := store.Create(ctx, sampleStatus("evt_del")); err != nil {
		t.Fatal(err)
	}
	if err := store.Delete(ctx, "evt_del"); err != nil {
		t.Fatalf("Delete failed: %v", err)
	}
	_, err := store.Get(ctx, "evt_del")
	if !errors.Is(err, status.ErrNotFound) {
		t.Errorf("expected ErrNotFound after Delete, got %v", err)
	}
}

func TestMemoryStore_Delete_NoopOnMissing(t *testing.T) {
	store := newStore()
	if err := store.Delete(context.Background(), "never_existed"); err != nil {
		t.Errorf("expected Delete to be no-op on missing key, got %v", err)
	}
}

// ── Concurrent access does not race ──────────────────────────────────────────

func TestMemoryStore_ConcurrentAccess(t *testing.T) {
	store := newStore()
	ctx := context.Background()

	const numEvents = 20
	// Pre-create all events
	for i := 0; i < numEvents; i++ {
		if err := store.Create(ctx, sampleStatus(fmt.Sprintf("evt_conc_%d", i))); err != nil {
			t.Fatal(err)
		}
	}

	var wg sync.WaitGroup
	for i := 0; i < numEvents; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			id := fmt.Sprintf("evt_conc_%d", idx)
			_ = store.UpdateStage(ctx, id, status.StageResult{
				ID: status.StageDetection, Label: "Detection", State: status.StateSuccess,
			})
			_ = store.UpdateOverall(ctx, id, status.OverallUpdate{
				Status: status.StatusProcessing, ConfidenceScore: 0.9,
			})
			_, _ = store.Get(ctx, id)
		}(i)
	}
	wg.Wait()
	// No assertions needed — the race detector (go test -race) catches races.
}

// ── DriftDetected zero-value is always written ────────────────────────────────

func TestMemoryStore_UpdateOverall_DriftDetectedFalseIsWritten(t *testing.T) {
	store := newStore()
	ctx := context.Background()

	s := sampleStatus("evt_drift")
	s.DriftDetected = true // start as true
	if err := store.Create(ctx, s); err != nil {
		t.Fatal(err)
	}

	// Patch with DriftDetected=false
	if err := store.UpdateOverall(ctx, "evt_drift", status.OverallUpdate{
		Status:        status.StatusParsed,
		DriftDetected: status.BoolPtr(false),
	}); err != nil {
		t.Fatal(err)
	}

	got, _ := store.Get(ctx, "evt_drift")
	if got.DriftDetected {
		t.Error("expected DriftDetected=false after UpdateOverall with false")
	}
}
