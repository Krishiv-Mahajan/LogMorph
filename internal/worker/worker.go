package worker

import (
	"context"
	"fmt"
	"log"
	"strings"
	"sync"
	"time"

	"github.com/Krishiv-Mahajan/LogMorph/internal/buffer"
	"github.com/Krishiv-Mahajan/LogMorph/internal/detection"
	"github.com/Krishiv-Mahajan/LogMorph/internal/models"
	"github.com/Krishiv-Mahajan/LogMorph/internal/normalization"
	"github.com/Krishiv-Mahajan/LogMorph/internal/parsing"
	"github.com/Krishiv-Mahajan/LogMorph/internal/state"
	"github.com/Krishiv-Mahajan/LogMorph/internal/storage/raw"
	"github.com/Krishiv-Mahajan/LogMorph/internal/validation"
)

// PipelineResult represents the outcome of running a RawEvent through the processing pipeline.
type PipelineResult struct {
	EventID        string
	UniversalEvent *models.UniversalEvent
	Valid          bool
	Errors         []validation.ValidationError
	Drift          models.DriftResult
}

// Worker coordinates raw event consumption, immutable storage, and the processing pipeline.
type Worker struct {
	buffer        buffer.RawBuffer
	idempotency   buffer.IdempotencyStore
	rawStore      raw.RawEventStore
	stateStore    state.Store
	detector      detection.Detector
	driftDetector detection.DriftDetector
	parserEngine  parsing.Engine
	normalizer    *normalization.Normalizer
	validator     validation.Validator

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

	// BatchSize is the maximum number of messages fetched per ReadGroup /
	// ClaimPending call. Default: 10.
	BatchSize int64

	// Concurrency is the maximum number of messages processed in parallel.
	// Default: 4.
	Concurrency int64
}

const (
	defaultLockTTLSeconds = 120
	defaultDoneTTLSeconds = 86400
	defaultBatchSize      = 10
	defaultConcurrency    = 4
)

// NewWorker initialises a processing worker.
//
// idempotency may be nil only in tests that explicitly opt out of idempotency;
// in production always supply a RedisIdempotencyStore.
func NewWorker(
	buf buffer.RawBuffer,
	idempotency buffer.IdempotencyStore,
	rawStore raw.RawEventStore,
	stateStore state.Store,
	detector detection.Detector,
	driftDetector detection.DriftDetector,
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
	if cfg.BatchSize <= 0 {
		cfg.BatchSize = defaultBatchSize
	}
	if cfg.Concurrency <= 0 {
		cfg.Concurrency = defaultConcurrency
	}

	w := &Worker{
		buffer:        buf,
		idempotency:   idempotency,
		rawStore:      rawStore,
		stateStore:    stateStore,
		detector:      detector,
		driftDetector: driftDetector,
		parserEngine:  parserEngine,
		normalizer:    normalizer,
		validator:     validator,
		streamName:    cfg.StreamName,
		groupName:     cfg.GroupName,
		consumerName:  cfg.ConsumerName,
		lockTTL:       time.Duration(cfg.LockTTLSeconds) * time.Second,
		doneTTL:       time.Duration(cfg.DoneTTLSeconds) * time.Second,
		batchSize:     cfg.BatchSize,
		concurrency:   cfg.Concurrency,
	}

	if cfg.ClaimIdleMs > 0 {
		w.claimIdleTime = time.Duration(cfg.ClaimIdleMs) * time.Millisecond
	}

	return w
}

// ProcessSingleEvent executes the immutable raw store copy and full processing
// pipeline for one event. It does NOT perform idempotency checks — those are
// handled by the caller (processSingleMessageIdempotent).
func (w *Worker) ProcessSingleEvent(ctx context.Context, rawEvent models.RawEvent) (*PipelineResult, error) {
	// Initialize state
	evtState := state.EventState{
		EventID:    rawEvent.EventID,
		Timestamp:  time.Now().Format(time.RFC3339),
		FormatName: rawEvent.Format,
		RawPayload: rawEvent.Payload,
		Status:     "Processing",
		Stages: map[string]state.StageResult{
			"ingestion":     {ID: "ingestion", Label: "Ingestion", State: state.StageSuccess, Detail: "OK"},
			"detection":     {ID: "detection", Label: "Detection", State: state.StageProcessing},
			"drift":         {ID: "drift", Label: "Drift", State: state.StageIdle},
			"parsing":       {ID: "parsing", Label: "Parsing", State: state.StageIdle},
			"normalization": {ID: "normalization", Label: "Normalization", State: state.StageIdle},
			"validation":    {ID: "validation", Label: "Validation", State: state.StageIdle},
		},
	}
	if w.stateStore != nil {
		_ = w.stateStore.UpdateEventState(ctx, evtState)
	}

	// 1. Immutable Raw Event Store (side-branch; path: raw-events/{event_id}.json)
	if w.rawStore != nil {
		if err := w.rawStore.Put(ctx, &rawEvent); err != nil {
			log.Printf("[Worker] Warning: failed to persist raw event %s to MinIO: %v", rawEvent.EventID, err)
		}
	}

	// 2. Format / Source Detection
	detectionRes := w.detector.Detect(rawEvent.Payload, rawEvent.Format)
	evtState.FormatName = detectionRes.Format
	evtState.ConfidenceScore = detectionRes.Confidence
	var detectionState state.StageState
	var detectionDetail string
	if detectionRes.Format == "unknown" {
		detectionState = state.StageWarning
		detectionDetail = "UNKNOWN FORMAT"
	} else {
		detectionState = state.StageSuccess
		detectionDetail = fmt.Sprintf("%s DETECTED", strings.ToUpper(detectionRes.Format))
	}

	evtState.Stages["detection"] = state.StageResult{ID: "detection", Label: "Detection", State: detectionState, Detail: detectionDetail}
	evtState.Stages["drift"] = state.StageResult{ID: "drift", Label: "Drift", State: state.StageProcessing}
	if w.stateStore != nil {
		_ = w.stateStore.UpdateEventState(ctx, evtState)
	}

	// 3. Drift Analysis
	driftRes, err := w.driftDetector.Analyze(ctx, rawEvent, detectionRes)
	if err != nil {
		log.Printf("[Worker] Drift analysis error for event %s: %v", rawEvent.EventID, err)
	}
	if driftRes.Status == models.DriftStatusUnknown || driftRes.Status == models.DriftStatusMajorDrift {
		log.Printf("[Worker] Drift alert: event %s classified as %s (%s)", rawEvent.EventID, driftRes.Status, driftRes.Message)
		
		evtState.DriftDetected = true
		evtState.Status = "Drift"
		evtState.ErrorMessage = driftRes.Message
		evtState.Stages["drift"] = state.StageResult{ID: "drift", Label: "Drift", State: state.StageWarning, Detail: "DRIFT DETECTED", Error: driftRes.Message}
		evtState.Stages["parsing"] = state.StageResult{ID: "parsing", Label: "Parsing", State: state.StageIdle, Detail: "Skipped"}
		if w.stateStore != nil {
			_ = w.stateStore.UpdateEventState(ctx, evtState)
			_ = w.stateStore.IncrementMetric(ctx, state.MetricDrift)
			_ = w.stateStore.IncrementMetric(ctx, state.MetricProcessed)
			_ = w.stateStore.PushRecentEvent(ctx, evtState)
		}
		
		return &PipelineResult{
			EventID: rawEvent.EventID,
			Drift:   driftRes,
		}, nil
	}

	evtState.Stages["drift"] = state.StageResult{ID: "drift", Label: "Drift", State: state.StageSuccess, Detail: "STABLE"}
	evtState.Stages["parsing"] = state.StageResult{ID: "parsing", Label: "Parsing", State: state.StageProcessing}
	if w.stateStore != nil {
		_ = w.stateStore.UpdateEventState(ctx, evtState)
	}

	// 4. Parser Engine
	parsedEvent, err := w.parserEngine.Parse(ctx, rawEvent, detectionRes)
	if err != nil {
		evtState.Status = "Error"
		evtState.ErrorMessage = err.Error()
		evtState.Stages["parsing"] = state.StageResult{ID: "parsing", Label: "Parsing", State: state.StageError, Detail: "Invalid syntax", Error: err.Error()}
		if w.stateStore != nil {
			_ = w.stateStore.UpdateEventState(ctx, evtState)
			_ = w.stateStore.IncrementMetric(ctx, state.MetricErrors)
			_ = w.stateStore.IncrementMetric(ctx, state.MetricProcessed)
			_ = w.stateStore.PushRecentEvent(ctx, evtState)
		}
		return nil, fmt.Errorf("parsing failed: %w", err)
	}

	evtState.Stages["parsing"] = state.StageResult{ID: "parsing", Label: "Parsing", State: state.StageSuccess, Detail: "Parsed"}
	evtState.Stages["normalization"] = state.StageResult{ID: "normalization", Label: "Normalization", State: state.StageProcessing}
	if w.stateStore != nil {
		_ = w.stateStore.UpdateEventState(ctx, evtState)
	}

	// 5. Normalization
	universalEvent, err := w.normalizer.Normalize(rawEvent, parsedEvent, detectionRes)
	if err != nil {
		evtState.Status = "Error"
		evtState.ErrorMessage = err.Error()
		evtState.Stages["normalization"] = state.StageResult{ID: "normalization", Label: "Normalization", State: state.StageError, Detail: "Normalization failed", Error: err.Error()}
		if w.stateStore != nil {
			_ = w.stateStore.UpdateEventState(ctx, evtState)
			_ = w.stateStore.IncrementMetric(ctx, state.MetricErrors)
			_ = w.stateStore.IncrementMetric(ctx, state.MetricProcessed)
			_ = w.stateStore.PushRecentEvent(ctx, evtState)
		}
		return nil, fmt.Errorf("normalization failed: %w", err)
	}

	evtState.Source = universalEvent.Source.Type
	if evtState.Source == "" {
		evtState.Source = universalEvent.Source.Vendor
	}
	evtState.Action = universalEvent.Event.Action
	evtState.ParserName = universalEvent.Metadata.ParserVersion
	evtState.UniversalEvent = universalEvent
	evtState.Stages["normalization"] = state.StageResult{ID: "normalization", Label: "Normalization", State: state.StageSuccess, Detail: "Standardized"}
	evtState.Stages["validation"] = state.StageResult{ID: "validation", Label: "Validation", State: state.StageProcessing}
	if w.stateStore != nil {
		_ = w.stateStore.UpdateEventState(ctx, evtState)
	}

	// 6. JSON Schema Validation
	valResult := w.validator.Validate(universalEvent)

	res := &PipelineResult{
		EventID:        universalEvent.EventID,
		UniversalEvent: universalEvent,
		Valid:          valResult.Valid,
		Errors:         valResult.Errors,
		Drift:          driftRes,
	}

	if valResult.Valid {
		evtState.Stages["validation"] = state.StageResult{ID: "validation", Label: "Validation", State: state.StageSuccess, Detail: "VALID"}
		evtState.Status = "Parsed"
		if w.stateStore != nil {
			_ = w.stateStore.UpdateEventState(ctx, evtState)
			_ = w.stateStore.IncrementMetric(ctx, state.MetricStable)
			_ = w.stateStore.IncrementMetric(ctx, state.MetricProcessed)
			_ = w.stateStore.PushRecentEvent(ctx, evtState)
		}
		
		netDetails := "n/a"
		if universalEvent.Network != nil {
			srcPort := 0
			if universalEvent.Network.SrcPort != nil {
				srcPort = *universalEvent.Network.SrcPort
			}
			dstPort := 0
			if universalEvent.Network.DstPort != nil {
				dstPort = *universalEvent.Network.DstPort
			}
			netDetails = fmt.Sprintf("%s:%d -> %s:%d (proto: %s)",
				universalEvent.Network.SrcIP, srcPort,
				universalEvent.Network.DstIP, dstPort,
				universalEvent.Network.Protocol)
		}
		log.Printf("[Worker] Processed event %s | format: %s | action: %s | net: %s | timestamp: %s",
			universalEvent.EventID,
			universalEvent.Raw.Format,
			universalEvent.Event.Action,
			netDetails,
			universalEvent.Timestamp,
		)
	} else {
		evtState.Stages["validation"] = state.StageResult{ID: "validation", Label: "Validation", State: state.StageWarning, Detail: "INVALID SCHEMA", Error: fmt.Sprintf("%v", valResult.Errors)}
		evtState.Status = "Error"
		evtState.ErrorMessage = "Validation failed"
		if w.stateStore != nil {
			_ = w.stateStore.UpdateEventState(ctx, evtState)
			_ = w.stateStore.IncrementMetric(ctx, state.MetricErrors)
			_ = w.stateStore.IncrementMetric(ctx, state.MetricProcessed)
			_ = w.stateStore.PushRecentEvent(ctx, evtState)
		}
		log.Printf("[Worker] Validation failed for event %s: %v", universalEvent.EventID, valResult.Errors)
	}

	return res, nil
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
		log.Printf("[Worker] Idempotency enabled: lock TTL=%s, done TTL=%s",
			w.lockTTL, w.doneTTL)
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
// top of Redis Streams' at-least-once delivery guarantee.
//
// Decision tree:
//
//  1. IsDone  → true:  already processed → skip side-effects, ACK
//  2. TryClaimProcessing → false: another worker has the lock → skip without ACK
//  3. TryClaimProcessing → true:  this worker owns the event
//     a. ProcessSingleEvent → error: release lock, do NOT ACK (XAUTOCLAIM retries)
//     b. ProcessSingleEvent → ok:   MarkDone, ACK
//
// When idempotency is nil (test mode / opt-out), falls back to the simple
// process+ACK path identical to the previous P0 behaviour.
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
			log.Printf("[Worker] Event %s already processed, skipping duplicate (ACK)", eventID)
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
			log.Printf("[Worker] Event %s locked by another worker, skipping without ACK", eventID)
			return
		}
	}

	// ── Pipeline ─────────────────────────────────────────────────────────────
	_, processErr := w.ProcessSingleEvent(ctx, msg.Event)

	if processErr != nil {
		log.Printf("[Worker] Error processing event %s (msg %s): %v", eventID, msg.ID, processErr)
		if w.idempotency != nil {
			// Release the processing lock so another worker can retry via XAUTOCLAIM.
			if err := w.idempotency.ReleaseProcessing(ctx, eventID); err != nil {
				log.Printf("[Worker] Warning: failed to release processing lock for %s: %v", eventID, err)
			}
		}
		// Do NOT ACK — message stays in PEL for XAUTOCLAIM-triggered retry.
		return
	}

	// ── Mark done + ACK ──────────────────────────────────────────────────────
	if w.idempotency != nil {
		if err := w.idempotency.MarkDone(ctx, eventID, w.doneTTL); err != nil {
			log.Printf("[Worker] Warning: failed to mark event %s as done: %v", eventID, err)
			// ACK anyway — event was processed successfully even if we can't record it.
		}
	}

	w.ack(ctx, msg)
}

// ack sends XACK for msg, logging any error.
func (w *Worker) ack(ctx context.Context, msg buffer.RawMessage) {
	if err := w.buffer.Ack(ctx, w.streamName, w.groupName, msg.ID); err != nil {
		log.Printf("[Worker] Failed to ack message %s: %v", msg.ID, err)
	}
}
