package ingestion

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/Krishiv-Mahajan/LogMorph/internal/state"
	"github.com/Krishiv-Mahajan/LogMorph/internal/storage/raw"
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
	service    Service
	stateStore state.Store
	rawStore   raw.RawEventStore
}

// NewHandler creates a new Ingestion API HTTP handler.
func NewHandler(service Service, stateStore state.Store, rawStore raw.RawEventStore) *Handler {
	return &Handler{
		service:    service,
		stateStore: stateStore,
		rawStore:   rawStore,
	}
}

// RegisterRoutes sets up HTTP routes on the given ServeMux.
func (h *Handler) RegisterRoutes(mux *http.ServeMux) {
	mux.HandleFunc("POST /ingest/batch", h.HandleIngestBatch)
	mux.HandleFunc("POST /ingest", h.HandleIngest)
	mux.HandleFunc("GET /health", h.HandleHealth)
	
	// Dashboard API
	mux.HandleFunc("GET /api/status", h.HandleStatus)
	mux.HandleFunc("GET /api/metrics", h.HandleMetrics)
	mux.HandleFunc("GET /api/events/recent", h.HandleRecentEvents)
	mux.HandleFunc("GET /api/events/{id}", h.HandleEventState)
}

// HandleHealth handles health check requests.
func (h *Handler) HandleHealth(w http.ResponseWriter, r *http.Request) {
	health := map[string]string{
		"backend": "ONLINE",
		"redis":   "ONLINE",
		"minio":   "UNKNOWN",
		"overall": "ONLINE",
	}
	
	if h.stateStore != nil {
		ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
		defer cancel()
		if err := h.stateStore.Ping(ctx); err != nil {
			health["redis"] = "OFFLINE"
			health["overall"] = "DEGRADED"
		}
	}

	if h.rawStore != nil {
		ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
		defer cancel()
		if err := h.rawStore.Ping(ctx); err != nil {
			health["minio"] = "OFFLINE"
			health["overall"] = "DEGRADED"
		} else {
			health["minio"] = "ONLINE"
		}
	}
	
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(health)
}

func (h *Handler) HandleStatus(w http.ResponseWriter, r *http.Request) {
	// Simple worker status since we don't have direct access to redis stream XINFO here easily.
	// In a full implementation, we'd query Redis.
	status := map[string]any{
		"worker_count": 1, // hardcoded for MVP unless we add XINFO GROUPS to stateStore
		"status": "ONLINE",
	}
	
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(status)
}

func (h *Handler) HandleMetrics(w http.ResponseWriter, r *http.Request) {
	if h.stateStore == nil {
		h.writeJSONError(w, http.StatusServiceUnavailable, ErrorResponse{Status: "error", Message: "State store uninitialized"})
		return
	}
	
	metrics, err := h.stateStore.GetMetrics(r.Context())
	if err != nil {
		h.writeJSONError(w, http.StatusInternalServerError, ErrorResponse{Status: "error", Message: err.Error()})
		return
	}
	
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(metrics)
}

func (h *Handler) HandleRecentEvents(w http.ResponseWriter, r *http.Request) {
	if h.stateStore == nil {
		h.writeJSONError(w, http.StatusServiceUnavailable, ErrorResponse{Status: "error", Message: "State store uninitialized"})
		return
	}
	
	events, err := h.stateStore.GetRecentEvents(r.Context(), 50)
	if err != nil {
		h.writeJSONError(w, http.StatusInternalServerError, ErrorResponse{Status: "error", Message: err.Error()})
		return
	}
	
	if events == nil {
		events = []state.EventState{}
	}
	
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(events)
}

func (h *Handler) HandleEventState(w http.ResponseWriter, r *http.Request) {
	if h.stateStore == nil {
		h.writeJSONError(w, http.StatusServiceUnavailable, ErrorResponse{Status: "error", Message: "State store uninitialized"})
		return
	}
	
	id := r.PathValue("id")
	if id == "" {
		h.writeJSONError(w, http.StatusBadRequest, ErrorResponse{Status: "error", Message: "Missing event ID"})
		return
	}
	
	evtState, err := h.stateStore.GetEventState(r.Context(), id)
	if err != nil {
		h.writeJSONError(w, http.StatusNotFound, ErrorResponse{Status: "error", Message: "Event not found"})
		return
	}
	
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(evtState)
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

func (h *Handler) writeJSONError(w http.ResponseWriter, status int, resp ErrorResponse) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(resp)
}
