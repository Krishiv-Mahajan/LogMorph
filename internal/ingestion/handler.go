package ingestion

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/google/uuid"

	"github.com/Krishiv-Mahajan/LogMorph/internal/models"
	"github.com/Krishiv-Mahajan/LogMorph/internal/normalization"
	"github.com/Krishiv-Mahajan/LogMorph/internal/redis"
	"github.com/Krishiv-Mahajan/LogMorph/internal/validation"
)

// IngestRequest represents the HTTP request payload for /ingest.
type IngestRequest struct {
	Format  string `json:"format,omitempty"`
	Source  string `json:"source,omitempty"`
	Payload string `json:"payload"`
}

// IngestResponse is returned on successful ingestion.
type IngestResponse struct {
	EventID string `json:"event_id"`
	Status  string `json:"status"`
}

// ErrorResponse is returned when ingestion or validation fails.
type ErrorResponse struct {
	EventID string                       `json:"event_id,omitempty"`
	Status  string                       `json:"status"`
	Message string                       `json:"message,omitempty"`
	Errors  []validation.ValidationError `json:"errors,omitempty"`
}

// Handler coordinates HTTP ingestion, normalization, validation, and Redis publication.
type Handler struct {
	normalizer *normalization.Normalizer
	validator  validation.Validator
	publisher  redis.StreamClient
	streamName string
}

// NewHandler creates a new Ingestion HTTP handler.
func NewHandler(normalizer *normalization.Normalizer, validator validation.Validator, publisher redis.StreamClient, streamName string) *Handler {
	if streamName == "" {
		streamName = redis.DefaultStreamName
	}
	return &Handler{
		normalizer: normalizer,
		validator:  validator,
		publisher:  publisher,
		streamName: streamName,
	}
}

// RegisterRoutes sets up HTTP routes on the given ServeMux.
func (h *Handler) RegisterRoutes(mux *http.ServeMux) {
	mux.HandleFunc("POST /ingest", h.HandleIngest)
	mux.HandleFunc("GET /health", h.HandleHealth)
}

// HandleHealth handles health check requests.
func (h *Handler) HandleHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}

// HandleIngest processes raw logs, normalizes, validates, and sends to Redis Stream.
func (h *Handler) HandleIngest(w http.ResponseWriter, r *http.Request) {
	var req IngestRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.writeJSONError(w, http.StatusBadRequest, ErrorResponse{
			Status:  "bad_request",
			Message: fmt.Sprintf("invalid JSON payload: %v", err),
		})
		return
	}

	if req.Payload == "" {
		h.writeJSONError(w, http.StatusBadRequest, ErrorResponse{
			Status:  "bad_request",
			Message: "payload must not be empty",
		})
		return
	}

	eventID := fmt.Sprintf("evt_%s", uuid.New().String())
	rawEvent := models.RawEvent{
		EventID:    eventID,
		ReceivedAt: time.Now().UTC().Format(time.RFC3339),
		Format:     req.Format,
		Source:     req.Source,
		Payload:    req.Payload,
	}

	// 1. Normalization
	universalEvent, err := h.normalizer.Normalize(rawEvent)
	if err != nil {
		h.writeJSONError(w, http.StatusUnprocessableEntity, ErrorResponse{
			EventID: eventID,
			Status:  "normalization_error",
			Message: err.Error(),
		})
		return
	}

	// 2. Validation
	valResult := h.validator.Validate(universalEvent)
	if !valResult.Valid {
		h.writeJSONError(w, http.StatusUnprocessableEntity, ErrorResponse{
			EventID: universalEvent.EventID,
			Status:  "validation_failed",
			Message: "event failed JSON schema validation",
			Errors:  valResult.Errors,
		})
		return
	}

	// 3. Publish to Redis Stream
	workerEvent := &models.WorkerEvent{
		EventID:       universalEvent.EventID,
		SchemaVersion: universalEvent.SchemaVersion,
		Event:         *universalEvent,
		Metadata: map[string]any{
			"published_at": time.Now().UTC().Format(time.RFC3339),
			"stream_name":  h.streamName,
		},
	}

	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()

	if h.publisher != nil {
		if _, err := h.publisher.PublishEvent(ctx, h.streamName, workerEvent); err != nil {
			h.writeJSONError(w, http.StatusInternalServerError, ErrorResponse{
				EventID: universalEvent.EventID,
				Status:  "publish_error",
				Message: fmt.Sprintf("failed to publish to Redis stream: %v", err),
			})
			return
		}
	}

	// 4. Success Response
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusAccepted)
	_ = json.NewEncoder(w).Encode(IngestResponse{
		EventID: universalEvent.EventID,
		Status:  "accepted",
	})
}

func (h *Handler) writeJSONError(w http.ResponseWriter, status int, resp ErrorResponse) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(resp)
}
