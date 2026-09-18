package parsers

// KeyValue is one key=value pair extracted from a syslog payload.
type KeyValue struct {
	Key   string
	Value string
}

// SyslogKeyValues returns the key=value pairs a syslog payload carries.
//
// It exports the same pattern the syslog parser itself uses, so schema
// observation can never disagree with parsing about which fields a payload
// contains.
func SyslogKeyValues(payload string) []KeyValue {
	matches := kvRegex.FindAllStringSubmatch(payload, -1)

	pairs := make([]KeyValue, 0, len(matches))
	for _, match := range matches {
		if len(match) != 3 {
			continue
		}
		pairs = append(pairs, KeyValue{Key: match[1], Value: match[2]})
	}

	return pairs
}
