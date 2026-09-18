package failure

import (
	"errors"
	"fmt"
	"testing"
)

func TestPermanentAndRetryableClassify(t *testing.T) {
	inner := errors.New("boom")

	perm := Permanent("evt_1", StageParsing, TypeParseFailed, inner)
	if perm.Class != ClassPermanent {
		t.Errorf("expected class %q, got %q", ClassPermanent, perm.Class)
	}
	if perm.Stage != StageParsing {
		t.Errorf("expected stage %q, got %q", StageParsing, perm.Stage)
	}
	if perm.TypeCode() != TypeParseFailed {
		t.Errorf("expected type %q, got %q", TypeParseFailed, perm.TypeCode())
	}
	if IsRetryable(perm) {
		t.Error("a permanent failure must not be retryable")
	}

	retry := Retryable("evt_1", StagePersistence, TypePersistenceFailed, inner)
	if retry.Class != ClassRetryable {
		t.Errorf("expected class %q, got %q", ClassRetryable, retry.Class)
	}
	if !IsRetryable(retry) {
		t.Error("a retryable failure must be retryable")
	}
}

// TestErrorUnwrapsCause — the classification must not hide the underlying error.
func TestErrorUnwrapsCause(t *testing.T) {
	sentinel := errors.New("connection refused")
	wrapped := fmt.Errorf("insert failed: %w", sentinel)

	f := Retryable("evt_2", StagePersistence, TypePersistenceFailed, wrapped)

	if !errors.Is(f, sentinel) {
		t.Error("expected errors.Is to reach the original cause")
	}

	found, ok := As(f)
	if !ok {
		t.Fatal("expected As to extract the classified failure")
	}
	if found.TypeCode() != TypePersistenceFailed {
		t.Errorf("expected type %q, got %q", TypePersistenceFailed, found.TypeCode())
	}
}

// TestClassifyDefaults — an unclassified error is retryable, because discarding
// an event is worse than attempting it again. An already-classified error is
// returned unchanged.
func TestClassifyDefaults(t *testing.T) {
	if got := Classify("evt", nil); got != nil {
		t.Errorf("expected nil for a nil error, got %v", got)
	}

	unclassified := Classify("evt_3", errors.New("something odd"))
	if unclassified.Class != ClassRetryable {
		t.Errorf("expected unclassified errors to default to retryable, got %q", unclassified.Class)
	}
	if unclassified.Stage != StageUnknown {
		t.Errorf("expected stage %q, got %q", StageUnknown, unclassified.Stage)
	}
	if unclassified.TypeCode() != TypeUnknown {
		t.Errorf("expected type %q, got %q", TypeUnknown, unclassified.TypeCode())
	}

	classified := Retryable("evt_4", StageRawStore, TypeRawStoreFailed, errors.New("minio down"))
	if got := Classify("evt_4", classified); got != classified {
		t.Error("expected Classify to return an already-classified failure unchanged")
	}
}

// TestIsRetryableEdgeCases documents the contract used by the worker.
func TestIsRetryableEdgeCases(t *testing.T) {
	if IsRetryable(nil) {
		t.Error("a nil error is not a retryable failure")
	}
	if !IsRetryable(errors.New("unclassified")) {
		t.Error("an unclassified non-nil error defaults to retryable")
	}
}

// TestTypeCodeFallsBack — a failure constructed without a type must not produce
// an empty failure_type in the quarantine record.
func TestTypeCodeFallsBack(t *testing.T) {
	f := Permanent("evt_5", StageValidation, "", errors.New("x"))
	if f.TypeCode() != TypeUnknown {
		t.Errorf("expected %q, got %q", TypeUnknown, f.TypeCode())
	}
}
