package main

import (
	"context"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/Krishiv-Mahajan/LogMorph/internal/detection"
	"github.com/Krishiv-Mahajan/LogMorph/internal/ingestion"
	"github.com/Krishiv-Mahajan/LogMorph/internal/normalization"
	"github.com/Krishiv-Mahajan/LogMorph/internal/normalization/parsers"
	"github.com/Krishiv-Mahajan/LogMorph/internal/redis"
	"github.com/Krishiv-Mahajan/LogMorph/internal/validation"
)

func main() {
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	redisAddr := os.Getenv("REDIS_ADDR")
	if redisAddr == "" {
		redisAddr = "localhost:6379"
	}
	redisPassword := os.Getenv("REDIS_PASSWORD")
	streamName := os.Getenv("STREAM_NAME")
	if streamName == "" {
		streamName = redis.DefaultStreamName
	}

	log.Println("[Ingestion] Initializing ULPF Ingestion Service...")

	// 1. Detection
	detector := detection.NewDetector()

	// 2. Parsers & Registry
	registry := normalization.NewRegistry()
	registry.Register(parsers.NewSyslogParser())
	registry.Register(parsers.NewJSONParser())
	registry.Register(parsers.NewCSVParser())

	// 3. Normalizer
	normalizer := normalization.NewNormalizer(detector, registry)

	// 4. Validator
	validator, err := validation.NewValidator("")
	if err != nil {
		log.Fatalf("[Ingestion] Failed to initialize JSON Schema validator: %v", err)
	}

	// 5. Redis Client
	redisClient, err := redis.NewStreamClient(redisAddr, redisPassword, 0)
	if err != nil {
		log.Fatalf("[Ingestion] Failed to create Redis client: %v", err)
	}
	defer redisClient.Close()

	ctxPing, cancelPing := context.WithTimeout(context.Background(), 2*time.Second)
	if err := redisClient.Ping(ctxPing); err != nil {
		log.Printf("[Ingestion] Warning: Redis not reachable at %s (%v). Running in degraded mode.", redisAddr, err)
	} else {
		log.Printf("[Ingestion] Connected to Redis at %s", redisAddr)
	}
	cancelPing()

	// 6. Ingestion HTTP Handler
	handler := ingestion.NewHandler(normalizer, validator, redisClient, streamName)
	mux := http.NewServeMux()
	handler.RegisterRoutes(mux)

	server := &http.Server{
		Addr:         ":" + port,
		Handler:      mux,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
	}

	// Graceful shutdown handling
	stopChan := make(chan os.Signal, 1)
	signal.Notify(stopChan, os.Interrupt, syscall.SIGTERM)

	go func() {
		log.Printf("[Ingestion] HTTP API listening on :%s (endpoint: POST /ingest)", port)
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("[Ingestion] Server failed: %v", err)
		}
	}()

	<-stopChan
	log.Println("[Ingestion] Shutting down gracefully...")

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := server.Shutdown(shutdownCtx); err != nil {
		log.Printf("[Ingestion] Server shutdown error: %v", err)
	}
	log.Println("[Ingestion] Service stopped")
}
