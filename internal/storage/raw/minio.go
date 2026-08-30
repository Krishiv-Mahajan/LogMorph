package raw

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"

	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"

	"github.com/Krishiv-Mahajan/LogMorph/internal/models"
)

// MinIOConfig contains connection settings for MinIO.
type MinIOConfig struct {
	Endpoint        string
	AccessKeyID     string
	SecretAccessKey string
	UseSSL          bool
	BucketName      string
}

// MinIORawStore persists immutable raw events in MinIO / S3.
type MinIORawStore struct {
	client *minio.Client
	bucket string
}

// NewMinIORawStore connects to MinIO and ensures the target bucket exists.
func NewMinIORawStore(ctx context.Context, cfg MinIOConfig) (*MinIORawStore, error) {
	if cfg.BucketName == "" {
		cfg.BucketName = "raw-events"
	}

	client, err := minio.New(cfg.Endpoint, &minio.Options{
		Creds:  credentials.NewStaticV4(cfg.AccessKeyID, cfg.SecretAccessKey, ""),
		Secure: cfg.UseSSL,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create minio client: %w", err)
	}

	// Check / create bucket
	exists, err := client.BucketExists(ctx, cfg.BucketName)
	if err != nil {
		return nil, fmt.Errorf("failed to check bucket existence: %w", err)
	}
	if !exists {
		err = client.MakeBucket(ctx, cfg.BucketName, minio.MakeBucketOptions{})
		if err != nil {
			return nil, fmt.Errorf("failed to create bucket %q: %w", cfg.BucketName, err)
		}
		log.Printf("[MinIO] Created bucket %q", cfg.BucketName)
	}

	return &MinIORawStore{
		client: client,
		bucket: cfg.BucketName,
	}, nil
}

// Put writes an immutable RawEvent JSON object at raw-events/{event_id}.json
func (m *MinIORawStore) Put(ctx context.Context, event *models.RawEvent) error {
	if event == nil || event.EventID == "" {
		return fmt.Errorf("invalid raw event or empty event_id")
	}

	data, err := json.Marshal(event)
	if err != nil {
		return fmt.Errorf("failed to marshal raw event: %w", err)
	}

	objectName := fmt.Sprintf("%s.json", event.EventID)
	reader := bytes.NewReader(data)

	_, err = m.client.PutObject(ctx, m.bucket, objectName, reader, int64(len(data)), minio.PutObjectOptions{
		ContentType: "application/json",
	})
	if err != nil {
		return fmt.Errorf("failed to store raw event in minio: %w", err)
	}

	return nil
}

// Get retrieves a RawEvent JSON object by event ID.
func (m *MinIORawStore) Get(ctx context.Context, eventID string) (*models.RawEvent, error) {
	objectName := fmt.Sprintf("%s.json", eventID)
	obj, err := m.client.GetObject(ctx, m.bucket, objectName, minio.GetObjectOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to get raw event object: %w", err)
	}
	defer obj.Close()

	data, err := io.ReadAll(obj)
	if err != nil {
		return nil, fmt.Errorf("failed to read raw event content: %w", err)
	}

	var event models.RawEvent
	if err := json.Unmarshal(data, &event); err != nil {
		return nil, fmt.Errorf("failed to unmarshal raw event: %w", err)
	}

	return &event, nil
}

func (m *MinIORawStore) Ping(ctx context.Context) error {
	_, err := m.client.BucketExists(ctx, m.bucket)
	return err
}

func (m *MinIORawStore) Close() error {
	return nil
}
