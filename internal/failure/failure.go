// Package failure classifies pipeline errors so the worker can decide between
// retrying a message and quarantining it.
//
// The distinction is driven by the STAGE that failed:
//
//   - Data stages (parsing, normalization, validation) are deterministic: the
//     same input produces the same result on every attempt. Errors there are
//     permanent by default, which is what stops poison-pill events from
//     circulating in Redis forever.
//   - Infrastructure stages (raw store, persistence, quarantine) depend on
//     external systems and are retryable by default, so a temporary outage
//     never destroys an event.
//
// Constructors are always used explicitly, so the default only matters for
// errors that escaped classification.
package failure

import (
	"errors"
	"fmt"
)

// Stage identifies the pipeline stage in which a failure occurred.
type Stage string

const (
	StageRawStore      Stage = "raw_store"
	StageDetection     Stage = "detection"
	StageDrift         Stage = "drift"
	StageParsing       Stage = "parsing"
	StageNormalization Stage = "normalization"
	StageValidation    Stage = "validation"
	StagePersistence   Stage = "persistence"
	StageQuarantine    Stage = "quarantine"
	StageUnknown       Stage = "unknown"
)

// Class distinguishes retryable infrastructure failures from permanent
// event/data failures.
type Class string

const (
	// ClassPermanent marks a deterministic failure: retrying the same event
	// cannot succeed. Such events are quarantined and acknowledged.
	ClassPermanent Class = "permanent"
	// ClassRetryable marks a transient failure: the message is left in the
	// Redis pending list so XAUTOCLAIM can deliver it again later.
	ClassRetryable Class = "retryable"
)

// Failure type codes recorded on quarantine entries. They are stable,
// machine-readable identifiers intended for alerting and triage.
const (
	TypeParseFailed       = "parse_failed"     // parser could not parse the payload
	TypeParserNotFound    = "parser_not_found" // no parser registered for the detected format
	TypeNormalizeFailed   = "normalization_failed"
	TypeValidationFailed  = "schema_validation_failed"
	TypeRawStoreFailed    = "raw_store_unavailable"
	TypePersistenceFailed = "persistence_unavailable"
	TypeQuarantineFailed  = "quarantine_unavailable"
	TypeMaxAttempts       = "max_attempts_exceeded"
	TypeUnknown           = "unknown_error"
)

// Error is a classified pipeline error. It wraps the underlying cause so that
// errors.Is / errors.As keep working on the inner error.
type Error struct {
	EventID string
	Stage   Stage
	Class   Class
	Type    string
	Err     error
}

// Error implements the error interface.
func (e *Error) Error() string {
	if e.Err == nil {
		return fmt.Sprintf("[%s/%s] %s", e.Stage, e.Class, e.Type)
	}
	return fmt.Sprintf("[%s/%s] %s: %v", e.Stage, e.Class, e.Type, e.Err)
}

// Unwrap exposes the underlying cause to errors.Is / errors.As.
func (e *Error) Unwrap() error { return e.Err }

// TypeCode returns the failure type code, used as the quarantine failure_type.
func (e *Error) TypeCode() string {
	if e.Type == "" {
		return TypeUnknown
	}
	return e.Type
}

// Permanent constructs a permanent (non-retryable) failure.
func Permanent(eventID string, stage Stage, failureType string, err error) *Error {
	return &Error{EventID: eventID, Stage: stage, Class: ClassPermanent, Type: failureType, Err: err}
}

// Retryable constructs a retryable (transient) failure.
func Retryable(eventID string, stage Stage, failureType string, err error) *Error {
	return &Error{EventID: eventID, Stage: stage, Class: ClassRetryable, Type: failureType, Err: err}
}

// As extracts a classified *Error from err, if one is present anywhere in the
// chain.
func As(err error) (*Error, bool) {
	var f *Error
	if errors.As(err, &f) {
		return f, true
	}
	return nil, false
}

// Classify returns the classified *Error contained in err. Unclassified errors
// fall back to a retryable unknown-stage failure: losing an event is worse than
// attempting it again.
func Classify(eventID string, err error) *Error {
	if err == nil {
		return nil
	}
	if f, ok := As(err); ok {
		return f
	}
	return Retryable(eventID, StageUnknown, TypeUnknown, err)
}

// IsRetryable reports whether err should be retried rather than quarantined.
func IsRetryable(err error) bool {
	f, ok := As(err)
	if !ok {
		return err != nil
	}
	return f.Class != ClassPermanent
}
