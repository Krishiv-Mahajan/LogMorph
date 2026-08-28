package buffer

import (
	"context"
	"testing"
	"time"

	"github.com/Krishiv-Mahajan/LogMorph/internal/models"
)

// Compile-time assertion: RedisRawBuffer must satisfy RawBuffer.
// A missing method produces a clear compile error rather than a runtime panic.
var _ RawBuffer = (*RedisRawBuffer)(nil)

// TestNewRedisRawBuffer_MaxLen verifies that the maxLen value passed to the
// constructor is stored on the struct. No live Redis connection is required
// because go-redis lazily dials (NewClient does not actually connect).
func TestNewRedisRawBuffer_MaxLen(t *testing.T) {
	tests := []struct {
		name   string
		maxLen int64
	}{
		{"zero (unlimited)", 0},
		{"100k cap", 100000},
		{"small cap", 1000},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			buf, err := NewRedisRawBuffer("localhost:6379", "", 0, tc.maxLen)
			if err != nil {
				t.Fatalf("NewRedisRawBuffer returned unexpected error: %v", err)
			}
			if buf.maxLen != tc.maxLen {
				t.Errorf("expected maxLen=%d, got %d", tc.maxLen, buf.maxLen)
			}
		})
	}
}

// TestDefaultConstants confirms stream/group name constants have not drifted.
func TestDefaultConstants(t *testing.T) {
	if DefaultRawStreamName != "raw_events" {
		t.Errorf("DefaultRawStreamName changed: got %q", DefaultRawStreamName)
	}
	if DefaultGroupName != "ulpf-worker-group" {
		t.Errorf("DefaultGroupName changed: got %q", DefaultGroupName)
	}
}

// --- compile-time interface check via minimal mock ---

// mockFull satisfies RawBuffer so the compiler verifies that ClaimPending is
// a legitimate interface method and that new mocks can be written cleanly.
type mockFull struct{}

func (m *mockFull) PublishRaw(_ context.Context, _ string, _ *models.RawEvent) (string, error) {
	return "", nil
}
func (m *mockFull) EnsureGroup(_ context.Context, _, _ string) error { return nil }
func (m *mockFull) ReadGroup(_ context.Context, _, _, _ string, _ int64, _ time.Duration) ([]RawMessage, error) {
	return nil, nil
}
func (m *mockFull) Ack(_ context.Context, _, _ string, _ ...string) error { return nil }
func (m *mockFull) ClaimPending(_ context.Context, _, _, _ string, _ time.Duration, _ int64) ([]RawMessage, error) {
	return nil, nil
}
func (m *mockFull) Ping(_ context.Context) error { return nil }
func (m *mockFull) Close() error                 { return nil }

var _ RawBuffer = (*mockFull)(nil)
