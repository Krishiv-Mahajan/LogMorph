package worker

import (
	"context"
	"errors"
	"fmt"
	"log"
	"strings"
	"sync"
	"time"

	"github.com/Krishiv-Mahajan/LogMorph/internal/buffer"
	"github.com/Krishiv-Mahajan/LogMorph/internal/detection"
	"github.com/Krishiv-Mahajan/LogMorph/internal/drift"
	"github.com/Krishiv-Mahajan/LogMorph/internal/failure"
	"github.com/Krishiv-Mahajan/LogMorph/internal/models"
	"github.com/Krishiv-Mahajan/LogMorph/internal/normalization"
	"github.com/Krishiv-Mahajan/LogMorph/internal/parsing"
	"github.com/Krishiv-Mahajan/LogMorph/internal/registry"
	"github.com/Krishiv-Mahajan/LogMorph/internal/storage/normalized"
	"github.com/Krishiv-Mahajan/LogMorph/internal/storage/quarantine"
	"github.com/Krishiv-Mahajan/LogMorph/internal/storage/raw"
	"github.com/Krishiv-Mahajan/LogMorph/internal/validation"
)

// Outcome is the explicit result of running one event through the pipeline. The
// worker's ACK/retry decision is driven entirely by this value.
type Outcome string

const (
	// OutcomeSuccess: the event was parsed, normalized, validated, and stored.
	// The message is marked done and ACKed.
	OutcomeSuccess Outcome = "SUCCESS"

	// OutcomeQuarantined: the event failed deterministically. It is recorded in
	// the quarantine store, marked done, and ACKed so it cannot circulate in
	// Redis forever.
	OutcomeQuarantined Outcome = "QUARANTINED"

	// OutcomeRetryableFailure: an infrastructure dependency failed. The message
	// is left in the Redis pending list for XAUTOCLAIM to redeliver.
	OutcomeRetryableFailure Outcome = "RETRYABLE_FAILURE"
)

// PipelineResult represents the outcome of running a RawEvent through the processing pipeline.
type PipelineResult struct {
	EventID        string
	UniversalEvent *models.UniversalEvent
	Valid          bool
	Errors         []validation.ValidationError

	// Outcome is the explicit processing outcome (see Outcome constants).
	Outcome Outcome

	// Failure describes how the pipeline failed. Nil when Outcome is
	// OutcomeSuccess.
	Failure *failure.Error

	// Duration is the wall-clock time spent processing the event.
	Duration time.Duration

	// SchemaDrift is the single authoritative drift verdict for this event.
	// Nil when no drift analyzer is configured.
	SchemaDrift *drift.Result

	// Mapping is the parser/mapping version applied to this event.
	Mapping *registry.Entry

	// Bindings records the values the alias binder contributed.
	Bindings []drift.Binding

	// Provenance is the traceability block written to the event and its row.
	Provenance models.Provenance
}

// Worker coordinates raw event consumption, immutable storage, and the processing pipeline.
type Worker struct {
	buffer          buffer.RawBuffer
	idempotency     buffer.IdempotencyStore
	rawStore        raw.RawEventStore
	detector        detection.Detector
	parserEngine    parsing.Engine
	normalizer      *normalization.Normalizer
	validator       validation.Validator
	normalizedStore normalized.Store
	quarantineStore quarantine.Store
	driftAnalyzer   drift.Analyzer

	streamName   string
	groupName    string
	consumerName string

	// claimIdleTime is the minimum idle duration before XAUTOCLAIM reclaims a
	// pending message. 0 disables crash recovery.
	claimIdleTime time.Duration

	// lockTTL is the Redis processing-lock TTL for idempotency. A crashed
	// worker's lock automatically expires after this duration so XAUTOCLAIM
	// can trigger a successful retry.
	lockTTL time.Duration

	// doneTTL is the TTL for the "successfully processed" marker in Redis.
	doneTTL time.Duration

	// attemptTTL is the TTL for the per-event attempt counter in Redis.
	attemptTTL time.Duration

	// maxAttempts bounds retries of a retryable failure. 0 disables the bound
	// (retry indefinitely).
	maxAttempts int64

	// batchSize is the maximum number of messages fetched per ReadGroup /
	// ClaimPending call. Configurable via WORKER_BATCH_SIZE (default 10).
	batchSize int64

	// concurrency is the maximum number of events processed in parallel within
	// a batch. Configurable via WORKER_CONCURRENCY (default 4).
	concurrency int64
}

// Config provides configuration options for the worker.
type Config struct {
	StreamName   string
	GroupName    string
	ConsumerName string

	// ClaimIdleMs is the pending-message idle threshold in milliseconds used
	// for crash recovery (XAUTOCLAIM). 0 disables crash recovery.
	ClaimIdleMs int64

	// LockTTLSeconds is the processing-lock TTL in seconds. When a worker holds
	// the lock and crashes, the lock expires after this duration, allowing
	// XAUTOCLAIM to trigger a retry. Default: 120 s.
	LockTTLSeconds int64

	// DoneTTLSeconds is the TTL of the "successfully processed" marker in Redis.
	// Events processed within this window won't be reprocessed. Default: 86400 s.
	DoneTTLSeconds int64

	// AttemptTTLSeconds is the TTL of the per-event attempt counter. It should
	// comfortably exceed the retry window of a transient outage.
	// Default: 86400 s.
	AttemptTTLSeconds int64

	// MaxAttempts quarantines an event whose retryable failure persists across
	// this many attempts, so a permanent infrastructure fault cannot keep a
	// message in Redis forever. 0 disables the bound. Default: 10.
	MaxAttempts int64

	// BatchSize is the maximum number of messages fetched per ReadGroup /
	// ClaimPending call. Default: 10.
	BatchSize int64

	// Concurrency is the maximum number of messages processed in parallel.
	// Default: 4.
	Concurrency int64

	// NormalizedStore receives validated UniversalEvents. When nil, validated
	// events are not persisted (test/opt-out mode).
	NormalizedStore normalized.Store

	// QuarantineStore receives events that failed permanently. When nil,
	// permanent failures cannot be recorded and are left in Redis rather than
	// being discarded.
	QuarantineStore quarantine.Store

	// DriftAnalyzer performs registry-backed schema drift analysis. When nil,
	// the worker keeps the pre-registry behaviour: events are parsed from the
	// detected format and no provenance is recorded.
	DriftAnalyzer drift.Analyzer
}

const (
	defaultLockTTLSeconds    = 120
	defaultDoneTTLSeconds    = 86400
	defaultAttemptTTLSeconds = 86400
	defaultMaxAttempts       = 10
	defaultBatchSize         = 10
	defaultConcurrency       = 4
)

// NewWorker initialises a processing worker.
//
// idempotency may be nil only in tests that explicitly opt out of idempotency;
// in production always supply a RedisIdempotencyStore.
func NewWorker(
	buf buffer.RawBuffer,
	idempotency buffer.IdempotencyStore,
	rawStore raw.RawEventStore,
	detector detection.Detector,
	parserEngine parsing.Engine,
	normalizer *normalization.Normalizer,
	validator validation.Validator,
	cfg Config,
) *Worker {
	if cfg.StreamName == "" {
		cfg.StreamName = buffer.DefaultRawStreamName
	}
	if cfg.GroupName == "" {
		cfg.GroupName = buffer.DefaultGroupName
	}
	if cfg.ConsumerName == "" {
		cfg.ConsumerName = "worker-1"
	}
	if cfg.LockTTLSeconds <= 0 {
		cfg.LockTTLSeconds = defaultLockTTLSeconds
	}
	if cfg.DoneTTLSeconds <= 0 {
		cfg.DoneTTLSeconds = defaultDoneTTLSeconds
	}
	if cfg.AttemptTTLSeconds <= 0 {
		cfg.AttemptTTLSeconds = defaultAttemptTTLSeconds
	}
	if cfg.MaxAttempts <= 0 {
		cfg.MaxAttempts = defaultMaxAttempts
	}
	if cfg.BatchSize <= 0 {
		cfg.BatchSize = defaultBatchSize
	}
	if cfg.Concurrency <= 0 {
		cfg.Concurrency = defaultConcurrency
	}

	w := &Worker{
		buffer:          buf,
		idempotency:     idempotency,
		rawStore:        rawStore,
		detector:        detector,
		parserEngine:    parserEngine,
		normalizer:      normalizer,
		validator:       validator,
		normalizedStore: cfg.NormalizedStore,
		quarantineStore: cfg.QuarantineStore,
		driftAnalyzer:   cfg.DriftAnalyzer,
		streamName:      cfg.StreamName,
		groupName:       cfg.GroupName,
		consumerName:    cfg.ConsumerName,
		lockTTL:         time.Duration(cfg.LockTTLSeconds) * time.Second,
		doneTTL:         time.Duration(cfg.DoneTTLSeconds) * time.Second,
		attemptTTL:      time.Duration(cfg.AttemptTTLSeconds) * time.Second,
		maxAttempts:     cfg.MaxAttempts,
		batchSize:       cfg.BatchSize,
		concurrency:     cfg.Concurrency,
	}

	if cfg.ClaimIdleMs > 0 {
		w.claimIdleTime = time.Duration(cfg.ClaimIdleMs) * time.Millisecond
	}

	return w
}

// ProcessSingleEvent executes the immutable raw store copy, the full processing
// pipeline, and persistence of the normalized event for one event. It does NOT
// perform idempotency checks, ACK, or quarantine — those are handled by the
// caller (processSingleMessageIdempotent).
//
// The returned result is never nil and always carries an Outcome, so a caller
// cannot mistake a deterministic failure (invalid event) for success. The
// returned error is non-nil exactly when the outcome is not OutcomeSuccess.
func (w *Worker) ProcessSingleEvent(ctx context.Context, rawEvent models.RawEvent) (*PipelineResult, error) {
	started := time.Now()

	res := &PipelineResult{
		EventID: rawEvent.EventID,
		Outcome: OutcomeSuccess,
	}

	// 1. Immutable Raw Event Store (side-branch; path: raw-events/{event_id}.json)
	// A failure here is retryable: downstream records reference this object, so
	// storing them without it would leave a dangling reference.
	if w.rawStore != nil {
		if err := w.rawStore.Put(ctx, &rawEvent); err != nil {
			return w.failed(res, failure.Retryable(rawEvent.EventID, failure.StageRawStore,
				failure.TypeRawStoreFailed, err), started)
		}
	}

	// 2. Format / Source Detection
	detectionRes := w.detector.Detect(rawEvent.Payload, rawEvent.Format)

	// 3. Schema Drift Analysis + Source Registry resolution.
	//
	// This is the ONLY place a drift verdict is produced. Downstream stages
	// (parser selection, alias binding, provenance, quarantine and logging)
	// consume res.SchemaDrift and nothing else; no second drift computation
	// runs in this pipeline.
	//
	// It also decides which parser and mapping version own this source, and
	// records provenance for the stored event.
	schemaDrift := w.analyzeSchemaDrift(ctx, rawEvent, detectionRes)
	res.SchemaDrift = schemaDrift
	if schemaDrift != nil && schemaDrift.Entry != nil {
		res.Mapping = schemaDrift.Entry
	}
	// Provenance is captured before parsing so a parse or validation failure
	// still records which parser and mapping version was in force.
	res.Provenance = w.provenanceOf(res)

	// 4. Parser Engine
	// Deterministic: the same payload will fail the same way on every attempt,
	// so a parse failure is permanent rather than retryable.
	parserID := ""
	if res.Mapping != nil {
		parserID = res.Mapping.ParserID
	}
	parsedEvent, err := w.parserEngine.ParseWith(ctx, rawEvent, detectionRes, parserID)
	if err != nil {
		return w.failed(res, classifyParseFailure(rawEvent.EventID, err), started)
	}

	// 4b. Alias binding: apply declared aliases the parser does not implement
	// itself. The parser's own values always win.
	if schemaDrift != nil && schemaDrift.Entry != nil && len(schemaDrift.Observation.Fields) > 0 {
		res.Bindings = drift.Bind(parsedEvent, schemaDrift.Observation, schemaDrift.Entry.Contract)
	}

	// 5. Normalization
	// Deterministic, like parsing.
	universalEvent, err := w.normalizer.Normalize(rawEvent, parsedEvent, detectionRes)
	if err != nil {
		return w.failed(res, failure.Permanent(rawEvent.EventID, failure.StageNormalization,
			failure.TypeNormalizeFailed, err), started)
	}
	res.UniversalEvent = universalEvent
	res.EventID = universalEvent.EventID

	// 5b. Record the provenance on the event itself, so the stored payload is
	// self-describing even without the database columns.
	res.Provenance.Apply(&universalEvent.Metadata)

	// 6. JSON Schema Validation
	valResult := w.validator.Validate(universalEvent)
	res.Valid = valResult.Valid
	res.Errors = valResult.Errors

	if !valResult.Valid {
		return w.failed(res, failure.Permanent(universalEvent.EventID, failure.StageValidation,
			failure.TypeValidationFailed, fmt.Errorf("schema validation failed: %s", formatValidationErrors(valResult.Errors))), started)
	}

	// 7. Normalized Event Store (PostgreSQL)
	if w.normalizedStore != nil {
		_, err := w.normalizedStore.Save(ctx, normalized.Record{
			Event:        universalEvent,
			RawObjectKey: raw.ObjectKey(universalEvent.EventID),
			ReceivedAt:   parseReceivedAt(rawEvent.ReceivedAt),
			Provenance:   res.Provenance,
		})
		if err != nil {
			return w.failed(res, failure.Retryable(universalEvent.EventID, failure.StagePersistence,
				failure.TypePersistenceFailed, err), started)
		}
	}

	res.Duration = time.Since(started)

	return res, nil
}

// analyzeSchemaDrift resolves the source's parser/mapping and produces the
// event's single drift verdict.
//
// A registry failure is treated as non-fatal: the registry carries metadata and
// versioning, and losing that metadata is preferable to failing an event that
// could still be parsed and stored. The caller falls back to format-based
// parser selection when the result is nil.
//
// The escalation alert is emitted here, from the authoritative verdict, so it
// covers every outcome — including events that go on to fail parsing or
// validation, which is exactly when an operator needs the drift signal.
func (w *Worker) analyzeSchemaDrift(ctx context.Context, rawEvent models.RawEvent, detectionRes models.DetectionResult) *drift.Result {
	if w.driftAnalyzer == nil {
		return nil
	}

	result, err := w.driftAnalyzer.Analyze(ctx, rawEvent, detectionRes)
	if err != nil {
		log.Printf("[Worker] event_id=%s stage=drift outcome=degraded error=%q", rawEvent.EventID, err)
		return nil
	}

	// EscalationRequired covers both major_drift and unknown: the event cannot
	// be mapped deterministically and needs review.
	if result.EscalationRequired {
		log.Printf("[Worker] event_id=%s stage=drift outcome=alert status=%s reason=%q",
			rawEvent.EventID, result.Classification, result.Reason)
	}

	return result
}

// provenanceOf builds the traceability block for an event.
func (w *Worker) provenanceOf(res *PipelineResult) models.Provenance {
	provenance := models.Provenance{}

	if res.Mapping != nil {
		provenance.SourceFingerprint = res.Mapping.Fingerprint
		provenance.ParserID = res.Mapping.ParserID
		provenance.ParserVersion = res.Mapping.ParserVersion
		provenance.MappingID = res.Mapping.MappingID
		provenance.MappingVersion = res.Mapping.MappingVersion
	}
	if res.SchemaDrift != nil {
		provenance.DriftStatus = string(res.SchemaDrift.Classification)
	}

	return provenance
}

// failed records a classified failure on the result and returns it together
// with the error, so the caller can act on either.
func (w *Worker) failed(res *PipelineResult, f *failure.Error, started time.Time) (*PipelineResult, error) {
	res.Failure = f
	res.Duration = time.Since(started)

	if f.Class == failure.ClassPermanent {
		res.Outcome = OutcomeQuarantined
	} else {
		res.Outcome = OutcomeRetryableFailure
	}

	return res, f
}

// classifyParseFailure maps a parser-engine error to a failure type. Neither a
// missing parser nor an unparseable payload becomes parseable by trying again,
// so both are permanent; the type code distinguishes the two for triage.
func classifyParseFailure(eventID string, err error) *failure.Error {
	if errors.Is(err, parsing.ErrParserNotFound) {
		return failure.Permanent(eventID, failure.StageParsing, failure.TypeParserNotFound, err)
	}
	return failure.Permanent(eventID, failure.StageParsing, failure.TypeParseFailed, err)
}

// formatValidationErrors renders schema violations into a single readable
// string for the quarantine record.
func formatValidationErrors(errs []validation.ValidationError) string {
	if len(errs) == 0 {
		return "no validation details"
	}
	out := make([]string, 0, len(errs))
	for _, e := range errs {
		out = append(out, fmt.Sprintf("%s: %s", e.Field, e.Message))
	}
	return strings.Join(out, "; ")
}

// parseReceivedAt parses the ingestion timestamp into a time.Time, returning
// the zero time when it cannot be parsed.
func parseReceivedAt(value string) time.Time {
	if value == "" {
		return time.Time{}
	}
	t, err := time.Parse(time.RFC3339, value)
	if err != nil {
		return time.Time{}
	}
	return t.UTC()
}

// Start runs the continuous worker consumer loop until context cancellation.
//
// Crash recovery: when ClaimIdleMs > 0, the loop periodically calls
// ClaimPending (XAUTOCLAIM) to reclaim messages orphaned by crashed workers.
//
// Idempotency: each message goes through processSingleMessageIdempotent which
// uses Redis SET NX to ensure at-most-once side-effects despite at-least-once
// Redis Streams delivery.
func (w *Worker) Start(ctx context.Context) error {
	if err := w.buffer.EnsureGroup(ctx, w.streamName, w.groupName); err != nil {
		return fmt.Errorf("failed to ensure consumer group: %w", err)
	}

	log.Printf("[Worker] Listening on stream %q (group: %q, consumer: %q, batch: %d, concurrency: %d)",
		w.streamName, w.groupName, w.consumerName, w.batchSize, w.concurrency)

	// Schedule the first pending-message reclaim check.
	var nextClaimAt time.Time
	if w.claimIdleTime > 0 {
		nextClaimAt = time.Now().Add(w.claimIdleTime / 2)
		log.Printf("[Worker] Crash recovery enabled: reclaiming messages idle >%s (check every %s)",
			w.claimIdleTime, w.claimIdleTime/2)
	}

	if w.idempotency != nil {
		log.Printf("[Worker] Idempotency enabled: lock TTL=%s, done TTL=%s, attempt TTL=%s, max attempts=%d",
			w.lockTTL, w.doneTTL, w.attemptTTL, w.maxAttempts)
	}
	if w.normalizedStore == nil {
		log.Printf("[Worker] Warning: no normalized store configured — validated events will NOT be persisted")
	}
	if w.quarantineStore == nil {
		log.Printf("[Worker] Warning: no quarantine store configured — permanently failed events will stay in Redis")
	}

	for {
		select {
		case <-ctx.Done():
			log.Println("[Worker] Context cancelled, stopping worker...")
			return nil
		default:
		}

		// --- Crash recovery: reclaim pending messages from crashed consumers ---
		if w.claimIdleTime > 0 && time.Now().After(nextClaimAt) {
			nextClaimAt = time.Now().Add(w.claimIdleTime / 2)
			pending, claimErr := w.buffer.ClaimPending(
				ctx, w.streamName, w.groupName, w.consumerName, w.claimIdleTime, w.batchSize)
			if claimErr != nil {
				log.Printf("[Worker] Error claiming pending messages: %v", claimErr)
			} else if len(pending) > 0 {
				log.Printf("[Worker] Reclaimed %d pending message(s) from crashed consumers", len(pending))
				w.processMessages(ctx, pending)
			}
		}

		// --- Normal consumption of new messages ---
		messages, err := w.buffer.ReadGroup(ctx, w.streamName, w.groupName, w.consumerName, w.batchSize, 2*time.Second)
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			log.Printf("[Worker] Error reading stream: %v", err)
			time.Sleep(1 * time.Second)
			continue
		}

		w.processMessages(ctx, messages)
	}
}

// processMessages routes each message through idempotency-aware processing.
// When concurrency > 1, messages are processed in parallel bounded by a semaphore pool.
func (w *Worker) processMessages(ctx context.Context, messages []buffer.RawMessage) {
	if len(messages) == 0 {
		return
	}

	if w.concurrency <= 1 {
		for _, msg := range messages {
			if ctx.Err() != nil {
				return
			}
			w.processSingleMessageIdempotent(ctx, msg)
		}
		return
	}

	var wg sync.WaitGroup
	sem := make(chan struct{}, w.concurrency)

	for _, msg := range messages {
		if ctx.Err() != nil {
			break
		}

		select {
		case <-ctx.Done():
			break
		case sem <- struct{}{}:
		}

		wg.Add(1)
		go func(m buffer.RawMessage) {
			defer func() {
				<-sem
				wg.Done()
			}()
			w.processSingleMessageIdempotent(ctx, m)
		}(msg)
	}

	wg.Wait()
}

// processSingleMessageIdempotent enforces at-most-once processing semantics on
// top of Redis Streams' at-least-once delivery guarantee, and turns the
// pipeline outcome into an ACK/retry decision.
//
// Decision tree:
//
//  1. IsDone  → true:  already processed → skip side-effects, ACK
//  2. TryClaimProcessing → false: another worker has the lock → skip without ACK
//  3. TryClaimProcessing → true:  this worker owns the event
//     a. OutcomeSuccess        → MarkDone, ACK
//     b. OutcomeQuarantined    → quarantine, MarkDone, ACK (terminal: the
//     event must not stay in Redis forever)
//     c. OutcomeRetryableFailure → ReleaseProcessing, do NOT ACK
//     (XAUTOCLAIM redelivers later; if the attempt counter has
//     reached maxAttempts the event is quarantined instead)
//
// When idempotency is nil (test mode / opt-out), falls back to the simple
// process+ACK path.
func (w *Worker) processSingleMessageIdempotent(ctx context.Context, msg buffer.RawMessage) {
	eventID := msg.Event.EventID

	// ── Idempotency checks ───────────────────────────────────────────────────
	if w.idempotency != nil {
		// Fast path: event was already successfully processed — skip side-effects.
		done, err := w.idempotency.IsDone(ctx, eventID)
		if err != nil {
			log.Printf("[Worker] Warning: idempotency IsDone check failed for %s: %v (proceeding)", eventID, err)
			// Degraded mode: continue without idempotency guarantees if Redis is unavailable.
		} else if done {
			log.Printf("[Worker] event_id=%s outcome=skipped reason=already_processed (ACK)", eventID)
			w.ack(ctx, msg)
			return
		}

		// Atomic gate: only one worker may proceed past this point for a given eventID.
		claimed, err := w.idempotency.TryClaimProcessing(ctx, eventID, w.lockTTL)
		if err != nil {
			log.Printf("[Worker] Warning: idempotency claim failed for %s: %v (proceeding without lock)", eventID, err)
			// Degraded mode: treat as claimed so we don't loop indefinitely.
			claimed = true
		}
		if !claimed {
			// Another worker holds the processing lock.
			// Do NOT ACK — message stays in this consumer's PEL and will be
			// reclaimed by XAUTOCLAIM once the lock expires (after lockTTL).
			log.Printf("[Worker] event_id=%s outcome=deferred reason=locked_by_other_worker", eventID)
			return
		}
	}

	attempts := w.recordAttempt(ctx, eventID)

	// ── Pipeline ─────────────────────────────────────────────────────────────
	res, processErr := w.ProcessSingleEvent(ctx, msg.Event)
	if res == nil {
		// Defensive: ProcessSingleEvent always returns a result, but never
		// discard an event that produced neither a result nor an outcome.
		res = &PipelineResult{
			EventID: eventID,
			Outcome: OutcomeRetryableFailure,
			Failure: failure.Classify(eventID, processErr),
		}
	}

	// A result without a classification would panic on the log paths below;
	// synthesise one rather than losing the event.
	if res.Failure == nil && res.Outcome != OutcomeSuccess {
		res.Failure = failure.Classify(eventID, processErr)
	}

	switch res.Outcome {
	case OutcomeSuccess:
		// MarkDone failure is non-fatal: the event was processed successfully
		// even if the marker could not be recorded.
		w.markDoneQuietly(ctx, eventID)
		log.Printf("[Worker] event_id=%s stage=complete outcome=success format=%s action=%s net=%s mapping=%s drift=%s duration_ms=%d",
			eventID, formatOf(res), actionOf(res), netOf(res), mappingOf(res), driftOf(res), res.Duration.Milliseconds())
		w.ack(ctx, msg)

	case OutcomeQuarantined:
		if !w.writeQuarantine(ctx, msg, res, attempts, res.Failure) {
			// The failure is permanent, but we could not record it. Keeping the
			// message in Redis is the safe choice: the alternative silently
			// discards the event.
			log.Printf("[Worker] event_id=%s stage=%s outcome=quarantine_deferred reason=quarantine_write_failed",
				eventID, stageOf(res))
			w.releaseLock(ctx, eventID)
			return
		}

		log.Printf("[Worker] event_id=%s stage=%s outcome=quarantined type=%s class=%s attempts=%d duration_ms=%d error=%q",
			eventID, stageOf(res), res.Failure.TypeCode(), res.Failure.Class, attempts, res.Duration.Milliseconds(), res.Failure.Error())
		w.markDoneQuietly(ctx, eventID)
		w.ack(ctx, msg) // terminal: the event is safe in the quarantine store

	case OutcomeRetryableFailure:
		if w.maxAttempts > 0 && attempts >= w.maxAttempts {
			escalated := res.Failure
			if escalated == nil {
				escalated = failure.Retryable(eventID, failure.StageUnknown, failure.TypeUnknown, processErr)
			}
			escalated = failure.Permanent(eventID, escalated.Stage, failure.TypeMaxAttempts, escalated.Err)

			if w.writeQuarantine(ctx, msg, res, attempts, escalated) {
				log.Printf("[Worker] event_id=%s stage=%s outcome=quarantined type=%s class=%s attempts=%d reason=max_attempts_exceeded error=%q",
					eventID, escalated.Stage, escalated.Type, escalated.Class, attempts, escalated.Error())
				w.markDoneQuietly(ctx, eventID)
				w.ack(ctx, msg)
				return
			}

			// The quarantine write itself failed; fall through and retry.
			log.Printf("[Worker] event_id=%s stage=%s outcome=quarantine_deferred reason=quarantine_write_failed",
				eventID, escalated.Stage)
		}

		log.Printf("[Worker] event_id=%s stage=%s outcome=retryable_failure type=%s attempts=%d duration_ms=%d error=%q",
			eventID, stageOf(res), res.Failure.TypeCode(), attempts, res.Duration.Milliseconds(), res.Failure.Error())

		// Release the processing lock so another worker can retry via XAUTOCLAIM,
		// and do NOT ACK: the message stays in the PEL.
		w.releaseLock(ctx, eventID)
	}
}

// writeQuarantine records the event in the quarantine store. It reports whether
// the entry was durably written; when it returns false the caller must not ACK.
func (w *Worker) writeQuarantine(ctx context.Context, msg buffer.RawMessage, res *PipelineResult, attempts int64, f *failure.Error) bool {
	if w.quarantineStore == nil {
		log.Printf("[Worker] ERROR: event_id=%s cannot be quarantined: no quarantine store configured", msg.Event.EventID)
		return false
	}
	if f == nil {
		f = failure.Permanent(msg.Event.EventID, failure.StageUnknown, failure.TypeUnknown, nil)
	}

	eventID := msg.Event.EventID
	if eventID == "" {
		eventID = res.EventID
	}

	rawPayload := msg.Event
	err := w.quarantineStore.Add(ctx, quarantine.Entry{
		EventID:      eventID,
		Stage:        string(f.Stage),
		Type:         f.TypeCode(),
		Class:        string(f.Class),
		Message:      f.Error(),
		Attempts:     attempts,
		RawObjectKey: raw.ObjectKey(eventID),
		RawFormat:    msg.Event.Format,
		RawSource:    msg.Event.Source,
		StreamID:     msg.ID,
		ConsumerName: w.consumerName,
		ReceivedAt:   parseReceivedAt(msg.Event.ReceivedAt),
		RawPayload:   &rawPayload,
		Provenance:   res.Provenance,
	})
	if err != nil {
		log.Printf("[Worker] ERROR: failed to quarantine event %s (stream message %s): %v", eventID, msg.ID, err)
		return false
	}

	return true
}

// recordAttempt increments the per-event attempt counter. It returns 0 when the
// count is unavailable, which callers treat as "unknown" rather than as a
// reason to stop processing.
func (w *Worker) recordAttempt(ctx context.Context, eventID string) int64 {
	if w.idempotency == nil {
		return 0
	}

	attempts, err := w.idempotency.RecordAttempt(ctx, eventID, w.attemptTTL)
	if err != nil {
		log.Printf("[Worker] Warning: failed to record attempt for %s: %v", eventID, err)
		return 0
	}

	return attempts
}

// releaseLock drops the processing lock so a retry can claim the event again.
func (w *Worker) releaseLock(ctx context.Context, eventID string) {
	if w.idempotency == nil {
		return
	}
	if err := w.idempotency.ReleaseProcessing(ctx, eventID); err != nil {
		log.Printf("[Worker] Warning: failed to release processing lock for %s: %v", eventID, err)
	}
}

// markDoneQuietly records a terminal outcome (success or quarantine) so a
// re-delivered event takes the IsDone fast path instead of being reprocessed.
func (w *Worker) markDoneQuietly(ctx context.Context, eventID string) {
	if w.idempotency == nil {
		return
	}
	if err := w.idempotency.MarkDone(ctx, eventID, w.doneTTL); err != nil {
		log.Printf("[Worker] Warning: failed to mark event %s as done: %v", eventID, err)
	}
}

// ack sends XACK for msg, logging any error.
func (w *Worker) ack(ctx context.Context, msg buffer.RawMessage) {
	if err := w.buffer.Ack(ctx, w.streamName, w.groupName, msg.ID); err != nil {
		log.Printf("[Worker] Failed to ack message %s: %v", msg.ID, err)
	}
}

// ── Logging helpers ──────────────────────────────────────────────────────────

func stageOf(res *PipelineResult) string {
	if res.Failure == nil {
		return string(failure.StageUnknown)
	}
	return string(res.Failure.Stage)
}

func formatOf(res *PipelineResult) string {
	if res.UniversalEvent == nil {
		return "n/a"
	}
	return res.UniversalEvent.Raw.Format
}

func actionOf(res *PipelineResult) string {
	if res.UniversalEvent == nil {
		return "n/a"
	}
	return res.UniversalEvent.Event.Action
}

// mappingOf renders the parser/mapping version that processed an event.
func mappingOf(res *PipelineResult) string {
	if res.Mapping == nil {
		return "none"
	}
	return fmt.Sprintf("%s/v%d", res.Mapping.MappingID, res.Mapping.MappingVersion)
}

// driftOf renders the drift classification, noting when the mapping was
// adapted by this very event.
func driftOf(res *PipelineResult) string {
	if res.SchemaDrift == nil {
		return "unanalyzed"
	}

	status := string(res.SchemaDrift.Classification)
	if res.SchemaDrift.Adapted && res.Mapping != nil {
		status = fmt.Sprintf("%s(adapted=v%d)", status, res.Mapping.MappingVersion)
	}
	if res.SchemaDrift.EscalationRequired {
		status += "(review_required)"
	}

	return status
}

func netOf(res *PipelineResult) string {
	if res.UniversalEvent == nil || res.UniversalEvent.Network == nil {
		return "n/a"
	}

	net := res.UniversalEvent.Network
	srcPort := 0
	if net.SrcPort != nil {
		srcPort = *net.SrcPort
	}
	dstPort := 0
	if net.DstPort != nil {
		dstPort = *net.DstPort
	}

	return fmt.Sprintf("%s:%d -> %s:%d (proto: %s)", net.SrcIP, srcPort, net.DstIP, dstPort, net.Protocol)
}
