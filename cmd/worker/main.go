package main

import (
	"context"
	"log"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"github.com/Krishiv-Mahajan/LogMorph/internal/buffer"
	"github.com/Krishiv-Mahajan/LogMorph/internal/detection"
	"github.com/Krishiv-Mahajan/LogMorph/internal/normalization"
	"github.com/Krishiv-Mahajan/LogMorph/internal/parsing"
	"github.com/Krishiv-Mahajan/LogMorph/internal/parsing/parsers"
	"github.com/Krishiv-Mahajan/LogMorph/internal/storage/normalized"
	"github.com/Krishiv-Mahajan/LogMorph/internal/storage/postgres"
	"github.com/Krishiv-Mahajan/LogMorph/internal/storage/quarantine"
	"github.com/Krishiv-Mahajan/LogMorph/internal/storage/raw"
	"github.com/Krishiv-Mahajan/LogMorph/internal/validation"
	"github.com/Krishiv-Mahajan/LogMorph/internal/worker"
)

// postgresConnectAttempts / Delay bound how long worker startup waits for
// PostgreSQL. Later failures are handled per-event by the retry semantics.
const (
	postgresConnectAttempts = 15
	postgresConnectDelay    = 2 * time.Second
)

func main() {
	redisAddr := os.Getenv("REDIS_ADDR")
	if redisAddr == "" {
		redisAddr = "localhost:6379"
	}
	redisPassword := os.Getenv("REDIS_PASSWORD")

	rawStream := os.Getenv("RAW_STREAM_NAME")
	if rawStream == "" {
		rawStream = buffer.DefaultRawStreamName
	}
	groupName := os.Getenv("CONSUMER_GROUP")
	if groupName == "" {
		groupName = buffer.DefaultGroupName
	}
	consumerName := os.Getenv("CONSUMER_NAME")
	if consumerName == "" {
		consumerName = "worker-1"
	}

	minioEndpoint := os.Getenv("MINIO_ENDPOINT")
	if minioEndpoint == "" {
		minioEndpoint = "localhost:9000"
	}
	minioAccessKey := os.Getenv("MINIO_ACCESS_KEY")
	if minioAccessKey == "" {
		minioAccessKey = "minioadmin"
	}
	minioSecretKey := os.Getenv("MINIO_SECRET_KEY")
	if minioSecretKey == "" {
		minioSecretKey = "minioadminpassword"
	}
	minioBucket := os.Getenv("MINIO_BUCKET")
	if minioBucket == "" {
		minioBucket = "raw-events"
	}
	minioUseSSL := os.Getenv("MINIO_USE_SSL") == "true"

	// RAW_EVENT_STREAM_MAXLEN caps the Redis stream length approximately (0 = unlimited).
	maxLen, _ := strconv.ParseInt(os.Getenv("RAW_EVENT_STREAM_MAXLEN"), 10, 64)

	// RAW_EVENT_CLAIM_IDLE_MS is the pending-message idle threshold for crash recovery.
	// Defaults to 60000 ms (60 s). Set to 0 to disable crash recovery.
	claimIdleMs, _ := strconv.ParseInt(os.Getenv("RAW_EVENT_CLAIM_IDLE_MS"), 10, 64)
	if claimIdleMs == 0 {
		claimIdleMs = 60000
	}

	// IDEMPOTENCY_LOCK_TTL_S is the TTL in seconds for the processing lock (default 120 s).
	lockTTL, _ := strconv.ParseInt(os.Getenv("IDEMPOTENCY_LOCK_TTL_S"), 10, 64)

	// IDEMPOTENCY_DONE_TTL_S is the TTL in seconds for the completed event marker (default 86400 s / 24 h).
	doneTTL, _ := strconv.ParseInt(os.Getenv("IDEMPOTENCY_DONE_TTL_S"), 10, 64)

	// WORKER_BATCH_SIZE is the max count of messages to fetch per read/claim (default 10).
	batchSize, _ := strconv.ParseInt(os.Getenv("WORKER_BATCH_SIZE"), 10, 64)

	// WORKER_CONCURRENCY is the max number of events processed in parallel (default 4).
	concurrency, _ := strconv.ParseInt(os.Getenv("WORKER_CONCURRENCY"), 10, 64)

	// WORKER_MAX_ATTEMPTS caps retries of a retryable (infrastructure) failure.
	// Once the cap is reached the event is quarantined rather than retried
	// forever. 0 disables the cap. Default: 10.
	maxAttempts, _ := strconv.ParseInt(os.Getenv("WORKER_MAX_ATTEMPTS"), 10, 64)

	// WORKER_ATTEMPT_TTL_S is the TTL of the per-event attempt counter (default 86400 s).
	attemptTTL, _ := strconv.ParseInt(os.Getenv("WORKER_ATTEMPT_TTL_S"), 10, 64)

	log.Printf("[Worker] Initializing ULPF Processing Worker (Redis: %s, Stream: %s, Group: %s)...",
		redisAddr, rawStream, groupName)

	// 1. Redis Raw Stream Buffer & Idempotency Store
	rawBuffer, err := buffer.NewRedisRawBuffer(redisAddr, redisPassword, 0, maxLen)
	if err != nil {
		log.Fatalf("[Worker] Failed to create Redis buffer client: %v", err)
	}
	defer rawBuffer.Close()

	idempotencyStore := buffer.NewRedisIdempotencyStore(rawBuffer)

	// Wait for Redis connection
	for {
		ctxPing, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		if err := rawBuffer.Ping(ctxPing); err == nil {
			cancel()
			log.Println("[Worker] Connected to Redis")
			break
		} else {
			cancel()
			log.Printf("[Worker] Waiting for Redis at %s...", redisAddr)
			time.Sleep(2 * time.Second)
		}
	}

	// 2. Immutable Raw Event Store (MinIO with Memory fallback)
	ctxMinio, cancelMinio := context.WithTimeout(context.Background(), 5*time.Second)
	var rawStore raw.RawEventStore
	minioStore, err := raw.NewMinIORawStore(ctxMinio, raw.MinIOConfig{
		Endpoint:        minioEndpoint,
		AccessKeyID:     minioAccessKey,
		SecretAccessKey: minioSecretKey,
		BucketName:      minioBucket,
		UseSSL:          minioUseSSL,
	})
	cancelMinio()

	if err != nil {
		log.Printf("[Worker] Warning: MinIO unavailable at %s (%v). Using in-memory raw store fallback.", minioEndpoint, err)
		rawStore = raw.NewMemoryRawStore()
	} else {
		log.Printf("[Worker] Connected to MinIO raw store (bucket: %s) at %s", minioBucket, minioEndpoint)
		rawStore = minioStore
	}
	defer rawStore.Close()

	// 3. PostgreSQL: normalized event store + quarantine store
	pgCfg := postgres.ConfigFromEnv()

	ctxPG, cancelPG := context.WithTimeout(context.Background(), 60*time.Second)
	pgDB, err := postgres.OpenWithRetry(ctxPG, pgCfg, postgresConnectAttempts, postgresConnectDelay)
	cancelPG()
	if err != nil {
		// The normalized store is the terminal destination of the pipeline:
		// running without it would consume events that go nowhere.
		log.Fatalf("[Worker] Failed to connect to PostgreSQL at %s: %v", pgCfg.Redacted(), err)
	}
	defer pgDB.Close()
	log.Printf("[Worker] Connected to PostgreSQL (%s)", pgCfg.Redacted())

	if err := postgres.Migrate(context.Background(), pgDB); err != nil {
		log.Fatalf("[Worker] Failed to apply database migrations: %v", err)
	}

	normalizedStore := normalized.NewPostgresStore(pgDB)
	quarantineStore := quarantine.NewPostgresStore(pgDB)

	// 4. Detection & Drift
	detector := detection.NewDetector()
	driftDetector := detection.NewDriftDetector()

	// 5. Parser Engine & Registry
	registry := parsing.NewRegistry()
	registry.Register(parsers.NewSyslogParser())
	registry.Register(parsers.NewJSONParser())
	registry.Register(parsers.NewCSVParser())
	parserEngine := parsing.NewEngine(registry)

	// 6. Normalizer
	normalizer := normalization.NewNormalizer()

	// 7. JSON Schema Validator
	validator, err := validation.NewValidator("")
	if err != nil {
		log.Fatalf("[Worker] Failed to initialize JSON Schema validator: %v", err)
	}

	// 8. Worker Instance
	w := worker.NewWorker(
		rawBuffer,
		idempotencyStore,
		rawStore,
		detector,
		driftDetector,
		parserEngine,
		normalizer,
		validator,
		worker.Config{
			StreamName:        rawStream,
			GroupName:         groupName,
			ConsumerName:      consumerName,
			ClaimIdleMs:       claimIdleMs,
			LockTTLSeconds:    lockTTL,
			DoneTTLSeconds:    doneTTL,
			AttemptTTLSeconds: attemptTTL,
			MaxAttempts:       maxAttempts,
			BatchSize:         batchSize,
			Concurrency:       concurrency,
			NormalizedStore:   normalizedStore,
			QuarantineStore:   quarantineStore,
		},
	)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	stopChan := make(chan os.Signal, 1)
	signal.Notify(stopChan, os.Interrupt, syscall.SIGTERM)

	go func() {
		<-stopChan
		log.Println("[Worker] Shutting down...")
		cancel()
	}()

	if err := w.Start(ctx); err != nil {
		log.Printf("[Worker] Exited with error: %v", err)
	}
	log.Println("[Worker] Worker stopped")
}
