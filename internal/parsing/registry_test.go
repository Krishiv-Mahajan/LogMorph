package parsing

import (
	"context"
	"fmt"
	"sync"
	"testing"

	"github.com/Krishiv-Mahajan/LogMorph/internal/models"
)

type mockParser struct {
	format string
	tag    string
}

func (m *mockParser) Format() string {
	return m.format
}

func (m *mockParser) Parse(ctx context.Context, raw models.RawEvent) (*models.ParsedEvent, error) {
	return &models.ParsedEvent{}, nil
}

func TestRegistry_BasicOperations(t *testing.T) {
	reg := NewRegistry()

	syslogP := &mockParser{format: "syslog", tag: "syslog-v1"}
	jsonP := &mockParser{format: "json", tag: "json-v1"}
	csvP := &mockParser{format: "csv", tag: "csv-v1"}

	reg.Register(syslogP)
	reg.Register(jsonP)
	reg.Register(csvP)

	// Direct retrieval
	p, err := reg.Get("syslog")
	if err != nil {
		t.Fatalf("expected syslog parser, got error: %v", err)
	}
	if p.(*mockParser).tag != "syslog-v1" {
		t.Errorf("expected tag 'syslog-v1', got %q", p.(*mockParser).tag)
	}

	p, err = reg.Get("json")
	if err != nil {
		t.Fatalf("expected json parser, got error: %v", err)
	}
	if p.(*mockParser).tag != "json-v1" {
		t.Errorf("expected tag 'json-v1', got %q", p.(*mockParser).tag)
	}

	p, err = reg.Get("csv")
	if err != nil {
		t.Fatalf("expected csv parser, got error: %v", err)
	}
	if p.(*mockParser).tag != "csv-v1" {
		t.Errorf("expected tag 'csv-v1', got %q", p.(*mockParser).tag)
	}
}

func TestRegistry_CaseAndWhitespaceNormalization(t *testing.T) {
	reg := NewRegistry()

	// Register with mixed casing and whitespace
	reg.Register(&mockParser{format: "  Syslog  ", tag: "syslog-p"})
	reg.Register(&mockParser{format: "JSON", tag: "json-p"})
	reg.Register(&mockParser{format: "csv", tag: "csv-p"})

	testCases := []struct {
		lookupFormat string
		expectedTag  string
	}{
		{"syslog", "syslog-p"},
		{"Syslog", "syslog-p"},
		{"SYSLOG", "syslog-p"},
		{"  syslog  ", "syslog-p"},
		{"\tSysLog\n", "syslog-p"},
		{"json", "json-p"},
		{"Json", "json-p"},
		{" JSON ", "json-p"},
		{"csv", "csv-p"},
		{"CSV", "csv-p"},
		{"  CSV  ", "csv-p"},
	}

	for _, tc := range testCases {
		p, err := reg.Get(tc.lookupFormat)
		if err != nil {
			t.Errorf("Get(%q) unexpected error: %v", tc.lookupFormat, err)
			continue
		}
		if p.(*mockParser).tag != tc.expectedTag {
			t.Errorf("Get(%q) tag = %q, expected %q", tc.lookupFormat, p.(*mockParser).tag, tc.expectedTag)
		}
	}
}

func TestRegistry_UnregisteredAndEmptyFormat(t *testing.T) {
	reg := NewRegistry()
	reg.Register(&mockParser{format: "syslog", tag: "syslog-v1"})

	// Empty string
	if _, err := reg.Get(""); err == nil {
		t.Error("expected error for empty format, got nil")
	}

	// Whitespace only
	if _, err := reg.Get("   "); err == nil {
		t.Error("expected error for whitespace format, got nil")
	}

	// Unregistered format
	if _, err := reg.Get("xml"); err == nil {
		t.Error("expected error for unregistered format 'xml', got nil")
	}

	// Nil parser registration (defensive no-op)
	reg.Register(nil)
	reg.Register(&mockParser{format: "   ", tag: "blank"})
	if _, err := reg.Get("   "); err == nil {
		t.Error("expected blank format to not be registered")
	}
}

func TestRegistry_DuplicateRegistration(t *testing.T) {
	reg := NewRegistry()

	parserV1 := &mockParser{format: "json", tag: "v1"}
	parserV2 := &mockParser{format: "JSON", tag: "v2"}

	reg.Register(parserV1)
	p, err := reg.Get("json")
	if err != nil || p.(*mockParser).tag != "v1" {
		t.Fatalf("expected v1 parser, got: %v, err: %v", p, err)
	}

	// Re-registering with different case should overwrite/update
	reg.Register(parserV2)
	p, err = reg.Get("json")
	if err != nil || p.(*mockParser).tag != "v2" {
		t.Fatalf("expected v2 parser after duplicate registration, got: %v, err: %v", p, err)
	}
}

func TestRegistry_ConcurrentAccess(t *testing.T) {
	reg := NewRegistry()

	// Initial registrations
	reg.Register(&mockParser{format: "syslog", tag: "syslog-0"})
	reg.Register(&mockParser{format: "json", tag: "json-0"})
	reg.Register(&mockParser{format: "csv", tag: "csv-0"})

	var wg sync.WaitGroup
	workers := 20
	iterations := 100

	// Concurrent readers
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for j := 0; j < iterations; j++ {
				format := []string{"syslog", "Syslog", " JSON ", "csv", "unknown"}[j%5]
				p, err := reg.Get(format)
				if format == "unknown" {
					if err == nil {
						t.Errorf("worker %d expected error for unknown format", id)
					}
				} else {
					if err != nil || p == nil {
						t.Errorf("worker %d unexpected error for format %s: %v", id, format, err)
					}
				}
			}
		}(i)
	}

	// Concurrent writers
	for i := 0; i < workers/2; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for j := 0; j < iterations; j++ {
				format := fmt.Sprintf("dynamic_%d", j%5)
				reg.Register(&mockParser{format: format, tag: fmt.Sprintf("tag_%d_%d", id, j)})
			}
		}(i)
	}

	wg.Wait()
}
