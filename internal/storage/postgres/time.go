package postgres

import (
	"strings"
	"time"
)

// timeLayouts are the timestamp formats seen from the pipeline. Parsers emit
// RFC3339, but a stored event from an older or third-party producer may use one
// of the others.
var timeLayouts = []string{
	time.RFC3339Nano,
	time.RFC3339,
	"2006-01-02T15:04:05",
	"2006-01-02 15:04:05",
	"2006 Jan 02 15:04:05",
	"Jan _2 15:04:05",
}

// TimestampOrNil converts a timestamp string to a UTC time.Time for a
// TIMESTAMPTZ column, returning nil (SQL NULL) when it cannot be parsed.
//
// Persistence must never fail because a producer emitted an exotic timestamp
// format: the original string is always preserved in the event payload, so a
// NULL column loses nothing.
func TimestampOrNil(value string) any {
	value = strings.TrimSpace(value)
	if value == "" {
		return nil
	}

	for _, layout := range timeLayouts {
		if t, err := time.Parse(layout, value); err == nil {
			return t.UTC()
		}
	}

	return nil
}
