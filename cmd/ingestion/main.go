package main

import (
	"context"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/Krishiv-Mahajan/LogMorph/internal/buffer"
	"github.com/Krishiv-Mahajan/LogMorph/internal/ingestion"
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

	rawStream := os.Getenv("RAW_STREAM_NAME")
	if rawStream == "" {
		rawStream = buffer.DefaultRawStreamName
	}

	log.Println("[Ingestion] Initializing ULPF Ingestion Service...")

	// 1. Initialize Redis Raw Stream Buffer
	rawBuffer, err := buffer.NewRedisRawBuffer(redisAddr, redisPassword, 0)
	if err != nil {
		log.Fatalf("[Ingestion] Failed to connect to Redis buffer: %v", err)
	}
	defer rawBuffer.Close()

	ctxPing, cancelPing := context.WithTimeout(context.Background(), 2*time.Second)
	if err := rawBuffer.Ping(ctxPing); err != nil {
		log.Printf("[Ingestion] Warning: Redis not reachable at %s (%v).", redisAddr, err)
	} else {
		log.Printf("[Ingestion] Connected to Redis stream buffer (%s) at %s", rawStream, redisAddr)
	}
	cancelPing()

	// 2. Ingestion Service & HTTP Handler
	service := ingestion.NewService(rawBuffer, rawStream)
	handler := ingestion.NewHandler(service)

	mux := http.NewServeMux()
	handler.RegisterRoutes(mux)

	server := &http.Server{
		Addr:         ":" + port,
		Handler:      mux,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
	}

	// 3. Graceful Shutdown
	stopChan := make(chan os.Signal, 1)
	signal.Notify(stopChan, os.Interrupt, syscall.SIGTERM)

	go func() {
		log.Printf("[Ingestion] HTTP API listening on :%s (endpoint: POST /ingest)", port)
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("[Ingestion] Server error: %v", err)
		}
	}()

	<-stopChan
	log.Println("[Ingestion] Shutting down...")

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := server.Shutdown(shutdownCtx); err != nil {
		log.Printf("[Ingestion] Shutdown error: %v", err)
	}
	log.Println("[Ingestion] Service stopped")
}
