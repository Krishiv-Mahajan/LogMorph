package registry

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
)

// FingerprintInput is the pre-parse evidence used to identify a log source.
//
// Every component must be available BEFORE the payload is parsed and must be
// independent of the payload's field structure — otherwise a source that
// changes its schema would compute a different fingerprint and could never be
// recognised as the same source drifting. That is why the fingerprint is built
// from the transport-level identity (format, source hint, detected source type)
// and never from field names.
type FingerprintInput struct {
	Format     string
	Source     string
	SourceType string
}

// Fingerprint computes the stable identifier of a log source.
//
// It is a SHA-256 over the normalized transport identity, truncated to 32 hex
// characters: long enough to avoid collisions, short enough to log and index.
// Sources with the same format and source hint deliberately share a
// fingerprint, so adding an optional field does not fork the source identity.
func Fingerprint(in FingerprintInput) string {
	canonical := strings.Join([]string{
		normalize(in.Format),
		normalize(in.Source),
		normalize(in.SourceType),
	}, "\x1f")

	sum := sha256.Sum256([]byte(canonical))

	return hex.EncodeToString(sum[:])[:32]
}

func normalize(value string) string {
	return strings.ToLower(strings.TrimSpace(value))
}
