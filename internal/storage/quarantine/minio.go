package quarantine

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
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

// MinIOQuarantineStore persists quarantined events in MinIO / S3.
type MinIOQuarantineStore struct {
	client *minio.Client
	bucket string
}

// NewMinIOQuarantineStore connects to MinIO and ensures the target bucket exists.
func NewMinIOQuarantineStore(ctx context.Context, cfg MinIOConfig) (*MinIOQuarantineStore, error) {
	if cfg.BucketName == "" {
		cfg.BucketName = "quarantine-events"
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
		log.Printf("[MinIO] Created quarantine bucket %q", cfg.BucketName)
	}

	return &MinIOQuarantineStore{
		client: client,
		bucket: cfg.BucketName,
	}, nil
}

// Put writes an immutable QuarantineRecord JSON object at quarantine-events/{event_id}.json
func (m *MinIOQuarantineStore) Put(ctx context.Context, record *models.QuarantineRecord) error {
	if record == nil || record.EventID == "" {
		return fmt.Errorf("invalid quarantine record or empty event_id")
	}

	data, err := json.Marshal(record)
	if err != nil {
		return fmt.Errorf("failed to marshal quarantine record: %w", err)
	}

	objectName := fmt.Sprintf("%s.json", record.EventID)
	reader := bytes.NewReader(data)

	tags := map[string]string{
		"FailureStage":   record.FailureStage,
		"DetectedFormat": record.DetectedFormat,
		"EventID":        record.EventID,
	}

	_, err = m.client.PutObject(ctx, m.bucket, objectName, reader, int64(len(data)), minio.PutObjectOptions{
		ContentType:  "application/json",
		UserMetadata: tags,
	})
	if err != nil {
		return fmt.Errorf("failed to store quarantine record in minio: %w", err)
	}

	return nil
}
