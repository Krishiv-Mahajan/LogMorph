package ingestion

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/Krishiv-Mahajan/LogMorph/internal/status"
)

// IngestResponse is returned on successful event acceptance into the raw buffer.
type IngestResponse struct {
	EventID string `json:"event_id"`
	Status  string `json:"status"`
}

// ErrorResponse is returned when request validation or buffering fails.
type ErrorResponse struct {
	EventID string `json:"event_id,omitempty"`
	Status  string `json:"status"`
	Message string `json:"message"`
}

// Handler handles HTTP requests for log ingestion.
type Handler struct {
	service     Service
	statusStore status.Store // optional; nil disables GET /events/{id}/status
}

// NewHandler creates a new Ingestion HTTP handler without status tracking.
// Existing callers continue to work unchanged.
func NewHandler(service Service) *Handler {
	return NewHandlerWithStatus(service, nil)
}

// NewHandlerWithStatus creates a Handler that also exposes the event status
// endpoint. When statusStore is nil the status route returns 501 Not Implemented.
func NewHandlerWithStatus(service Service, statusStore status.Store) *Handler {
	return &Handler{
		service:     service,
		statusStore: statusStore,
	}
}

// RegisterRoutes sets up HTTP routes on the given ServeMux.
func (h *Handler) RegisterRoutes(mux *http.ServeMux) {
	mux.HandleFunc("POST /ingest/batch", h.HandleIngestBatch)
	mux.HandleFunc("POST /ingest", h.HandleIngest)
	mux.HandleFunc("GET /health", h.HandleHealth)
	mux.HandleFunc("GET /events/{event_id}/status", h.HandleGetEventStatus)
}

// HandleHealth handles health check requests.
func (h *Handler) HandleHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}

// HandleIngest accepts a single raw log payload and buffers it immediately into Redis.
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

	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()

	eventID, err := h.service.Ingest(ctx, req)
	if err != nil {
		h.writeJSONError(w, http.StatusInternalServerError, ErrorResponse{
			Status:  "ingestion_error",
			Message: err.Error(),
		})
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusAccepted)
	_ = json.NewEncoder(w).Encode(IngestResponse{
		EventID: eventID,
		Status:  "accepted",
	})
}

// HandleIngestBatch accepts an array of raw log payloads and buffers all of them into Redis.
func (h *Handler) HandleIngestBatch(w http.ResponseWriter, r *http.Request) {
	var reqs []IngestRequest
	if err := json.NewDecoder(r.Body).Decode(&reqs); err != nil {
		h.writeJSONError(w, http.StatusBadRequest, ErrorResponse{
			Status:  "bad_request",
			Message: fmt.Sprintf("invalid JSON batch payload: %v", err),
		})
		return
	}

	if len(reqs) == 0 {
		h.writeJSONError(w, http.StatusBadRequest, ErrorResponse{
			Status:  "bad_request",
			Message: "batch must not be empty",
		})
		return
	}

	for i, req := range reqs {
		if req.Payload == "" {
			h.writeJSONError(w, http.StatusBadRequest, ErrorResponse{
				Status:  "bad_request",
				Message: fmt.Sprintf("item at index %d has empty payload", i),
			})
			return
		}
	}

	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()

	eventIDs, err := h.service.IngestBatch(ctx, reqs)
	if err != nil {
		h.writeJSONError(w, http.StatusInternalServerError, ErrorResponse{
			Status:  "ingestion_error",
			Message: err.Error(),
		})
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusAccepted)
	_ = json.NewEncoder(w).Encode(BatchIngestResponse{
		Status:   "accepted",
		Count:    len(eventIDs),
		EventIDs: eventIDs,
	})
}

// HandleGetEventStatus returns the current processing status for an event.
//
//	GET /events/{event_id}/status
//
// Responses:
//   - 200 OK        — EventStatus JSON
//   - 404 Not Found — event_id does not exist in the status store
//   - 501            — status store not configured
func (h *Handler) HandleGetEventStatus(w http.ResponseWriter, r *http.Request) {
	if h.statusStore == nil {
		h.writeJSONError(w, http.StatusNotImplemented, ErrorResponse{
			Status:  "not_implemented",
			Message: "status tracking is not enabled",
		})
		return
	}

	eventID := r.PathValue("event_id")
	if eventID == "" {
		h.writeJSONError(w, http.StatusBadRequest, ErrorResponse{
			Status:  "bad_request",
			Message: "event_id is required",
		})
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()

	s, err := h.statusStore.Get(ctx, eventID)
	if err != nil {
		if errors.Is(err, status.ErrNotFound) {
			h.writeJSONError(w, http.StatusNotFound, ErrorResponse{
				Status:  "not_found",
				Message: "event status not found",
			})
			return
		}
		h.writeJSONError(w, http.StatusInternalServerError, ErrorResponse{
			Status:  "internal_error",
			Message: "failed to retrieve event status",
		})
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(s)
}

func (h *Handler) writeJSONError(w http.ResponseWriter, statusCode int, resp ErrorResponse) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	_ = json.NewEncoder(w).Encode(resp)
}
