package worker

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/Krishiv-Mahajan/LogMorph/internal/buffer"
	"github.com/Krishiv-Mahajan/LogMorph/internal/detection"
	"github.com/Krishiv-Mahajan/LogMorph/internal/models"
	"github.com/Krishiv-Mahajan/LogMorph/internal/normalization"
	"github.com/Krishiv-Mahajan/LogMorph/internal/parsing"
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
	rawStore      raw.RawEventStore
	detector      detection.Detector
	driftDetector detection.DriftDetector
	parserEngine  parsing.Engine
	normalizer    *normalization.Normalizer
	validator     validation.Validator

	streamName    string
	groupName     string
	consumerName  string
	// claimIdleTime is the minimum idle duration a pending message must have before
	// this worker will reclaim it via XAUTOCLAIM. 0 means crash recovery is disabled.
	claimIdleTime time.Duration
}

// Config provides configuration options for the worker.
type Config struct {
	StreamName   string
	GroupName    string
	ConsumerName string
	// ClaimIdleMs is the pending-message idle threshold in milliseconds used for
	// crash recovery (XAUTOCLAIM). 0 disables crash recovery. Default: 60000 (60 s).
	ClaimIdleMs int64
}

// NewWorker initializes a processing worker.
func NewWorker(
	buf buffer.RawBuffer,
	rawStore raw.RawEventStore,
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

	w := &Worker{
		buffer:        buf,
		rawStore:      rawStore,
		detector:      detector,
		driftDetector: driftDetector,
		parserEngine:  parserEngine,
		normalizer:    normalizer,
		validator:     validator,
		streamName:    cfg.StreamName,
		groupName:     cfg.GroupName,
		consumerName:  cfg.ConsumerName,
	}

	if cfg.ClaimIdleMs > 0 {
		w.claimIdleTime = time.Duration(cfg.ClaimIdleMs) * time.Millisecond
	}

	return w
}

// ProcessSingleEvent executes the immutable raw store copy and full processing pipeline for one event.
func (w *Worker) ProcessSingleEvent(ctx context.Context, rawEvent models.RawEvent) (*PipelineResult, error) {
	// 1. Immutable Raw Event Store (Side-branch)
	if w.rawStore != nil {
		if err := w.rawStore.Put(ctx, &rawEvent); err != nil {
			log.Printf("[Worker] Warning: failed to persist raw event %s to MinIO: %v", rawEvent.EventID, err)
		}
	}

	// 2. Format / Source Detection
	detectionRes := w.detector.Detect(rawEvent.Payload, rawEvent.Format)

	// 3. Drift Analysis (MVP deterministic check)
	driftRes, err := w.driftDetector.Analyze(ctx, rawEvent, detectionRes)
	if err != nil {
		log.Printf("[Worker] Drift analysis error for event %s: %v", rawEvent.EventID, err)
	}
	if driftRes.Status == models.DriftStatusUnknown || driftRes.Status == models.DriftStatusMajorDrift {
		log.Printf("[Worker] Drift alert: event %s classified as %s (%s)", rawEvent.EventID, driftRes.Status, driftRes.Message)
	}

	// 4. Parser Engine
	parsedEvent, err := w.parserEngine.Parse(ctx, rawEvent, detectionRes)
	if err != nil {
		return nil, fmt.Errorf("parsing failed: %w", err)
	}

	// 5. Normalization
	universalEvent, err := w.normalizer.Normalize(rawEvent, parsedEvent, detectionRes)
	if err != nil {
		return nil, fmt.Errorf("normalization failed: %w", err)
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
		log.Printf("[Worker] Validation failed for event %s: %v", universalEvent.EventID, valResult.Errors)
	}

	return res, nil
}

// Start runs the continuous worker consumer loop until context cancellation.
//
// Crash recovery: when ClaimIdleMs > 0, the loop periodically calls ClaimPending
// (XAUTOCLAIM) to reclaim messages that were delivered to a crashed consumer and
// never acknowledged. The reclaim interval is half the idle threshold.
func (w *Worker) Start(ctx context.Context) error {
	if err := w.buffer.EnsureGroup(ctx, w.streamName, w.groupName); err != nil {
		return fmt.Errorf("failed to ensure consumer group: %w", err)
	}

	log.Printf("[Worker] Listening on stream %q (group: %q, consumer: %q)",
		w.streamName, w.groupName, w.consumerName)

	// Schedule the first pending-message reclaim check.
	var nextClaimAt time.Time
	if w.claimIdleTime > 0 {
		nextClaimAt = time.Now().Add(w.claimIdleTime / 2)
		log.Printf("[Worker] Crash recovery enabled: reclaiming messages idle >%s (check every %s)",
			w.claimIdleTime, w.claimIdleTime/2)
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
				ctx, w.streamName, w.groupName, w.consumerName, w.claimIdleTime, 10)
			if claimErr != nil {
				log.Printf("[Worker] Error claiming pending messages: %v", claimErr)
			} else if len(pending) > 0 {
				log.Printf("[Worker] Reclaimed %d pending message(s) from crashed consumers", len(pending))
				w.processMessages(ctx, pending)
			}
		}

		// --- Normal consumption of new messages ---
		messages, err := w.buffer.ReadGroup(ctx, w.streamName, w.groupName, w.consumerName, 10, 2*time.Second)
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

// processMessages runs each message through the pipeline and ACKs it.
// It mirrors the previous inline loop so the behaviour is identical whether
// messages came from ReadGroup or ClaimPending.
func (w *Worker) processMessages(ctx context.Context, messages []buffer.RawMessage) {
	for _, msg := range messages {
		if ctx.Err() != nil {
			return
		}
		_, processErr := w.ProcessSingleEvent(ctx, msg.Event)
		if processErr != nil {
			log.Printf("[Worker] Error processing message %s (event %s): %v", msg.ID, msg.Event.EventID, processErr)
		}

		// Acknowledge processed message in Redis (matches existing ACK-even-on-error semantics).
		if err := w.buffer.Ack(ctx, w.streamName, w.groupName, msg.ID); err != nil {
			log.Printf("[Worker] Failed to ack message %s: %v", msg.ID, err)
		}
	}
}
