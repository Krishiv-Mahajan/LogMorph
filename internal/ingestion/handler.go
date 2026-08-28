package ingestion

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
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
	service Service
}

// NewHandler creates a new Ingestion HTTP handler.
func NewHandler(service Service) *Handler {
	return &Handler{
		service: service,
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

// HandleIngest accepts raw log payloads and buffers them immediately into Redis.
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

func (h *Handler) writeJSONError(w http.ResponseWriter, status int, resp ErrorResponse) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(resp)
}
