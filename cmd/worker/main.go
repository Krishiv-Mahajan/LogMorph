package main

import (
	"context"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/Krishiv-Mahajan/LogMorph/internal/redis"
	"github.com/Krishiv-Mahajan/LogMorph/internal/worker"
)

func main() {
	redisAddr := os.Getenv("REDIS_ADDR")
	if redisAddr == "" {
		redisAddr = "localhost:6379"
	}
	redisPassword := os.Getenv("REDIS_PASSWORD")
	streamName := os.Getenv("STREAM_NAME")
	if streamName == "" {
		streamName = redis.DefaultStreamName
	}
	groupName := os.Getenv("CONSUMER_GROUP")
	if groupName == "" {
		groupName = redis.DefaultGroupName
	}
	consumerName := os.Getenv("CONSUMER_NAME")
	if consumerName == "" {
		consumerName = "worker-1"
	}

	log.Printf("[Worker] Initializing ULPF Worker (Redis: %s, Stream: %s, Group: %s)...",
		redisAddr, streamName, groupName)

	redisClient, err := redis.NewStreamClient(redisAddr, redisPassword, 0)
	if err != nil {
		log.Fatalf("[Worker] Failed to create Redis client: %v", err)
	}
	defer redisClient.Close()

	// Wait for Redis to be ready
	for {
		ctxPing, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		if err := redisClient.Ping(ctxPing); err == nil {
			cancel()
			log.Println("[Worker] Successfully connected to Redis")
			break
		} else {
			cancel()
			log.Printf("[Worker] Waiting for Redis at %s (%v)...", redisAddr, err)
			time.Sleep(2 * time.Second)
		}
	}

	w := worker.NewWorker(redisClient, worker.Config{
		StreamName:   streamName,
		GroupName:    groupName,
		ConsumerName: consumerName,
	})

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
		log.Printf("[Worker] Worker exited with error: %v", err)
	}
	log.Println("[Worker] Worker stopped")
}
