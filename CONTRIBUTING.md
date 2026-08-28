# Contributing to ULPF (Universal Log Processing Framework)

Welcome to **ULPF**! This document outlines package boundaries, architecture rules, and developer workflows so multiple teammates can collaborate cleanly and in parallel.

---

## 1. Architectural Rules (Must Read)

1. **Raw Event Buffer is First**:
   The Ingestion service (`cmd/ingestion`, `internal/ingestion`) only receives logs, wraps them into `models.RawEvent`, and buffers them into Redis Streams (`raw_events`). Ingestion **does not** parse or normalize logs.

2. **Raw Event Store is an Immutable Side-Branch**:
   The Processing Worker (`cmd/worker`, `internal/worker`) saves an unaltered copy of every `RawEvent` to MinIO/S3 (`raw-events/{event_id}.json`) upon receipt. The processing pipeline runs on the raw event independently and **never** mutates the raw copy.

3. **Pipelines are Format-Independent**:
   All format-specific logic resides in `internal/parsing/parsers/`. Normalization, validation, drift analysis, and downstream consumers operate on canonical domain structs (`models.ParsedEvent`, `models.UniversalEvent`).

4. **Go vs. Python Responsibility Split**:
   - **Go**: High-throughput ingestion, buffering, parsing engine, normalization, schema validation, and storage connectors.
   - **Python (Future Phase)**: AI escalation, LLM/RAG mapping generation, and ML-based drift analysis.

---

## 2. Package Boundaries & Responsibilities

| Package | Path | Responsibility |
| :--- | :--- | :--- |
| **`models`** | `internal/models/` | Shared domain types (`RawEvent`, `ParsedEvent`, `UniversalEvent`, `DetectionResult`, `DriftResult`). |
| **`ingestion`** | `internal/ingestion/` | HTTP `/ingest` handler and service. Buffers raw events to Redis. |
| **`buffer`** | `internal/buffer/` | Redis Streams abstraction (`raw_events` stream, consumer groups, ack). |
| **`storage/raw`** | `internal/storage/raw/` | MinIO / S3 immutable raw event store (`raw-events/{event_id}.json`). |
| **`detection`** | `internal/detection/` | Deterministic format/source detector (`detector.go`) and drift analyzer (`drift.go`). |
| **`parsing`** | `internal/parsing/` | Parser interface (`parser.go`), registry (`registry.go`), engine (`engine.go`), and parsers (`parsers/syslog.go`, `parsers/json.go`, `parsers/csv.go`). |
| **`normalization`**| `internal/normalization/` | Converts `ParsedEvent` + `RawEvent` into canonical `UniversalEvent` v1.0. |
| **`validation`** | `internal/validation/` | JSON Schema validator validating `UniversalEvent` against `contracts/universal_event.schema.json`. |
| **`worker`** | `internal/worker/` | Consumer group worker loop coordinating storage and pipeline stages. |

---

## 3. How to Add a New Log Parser

To support a new log format (e.g., `cef`, `leef`, `winevent`):

1. Create a new parser file in `internal/parsing/parsers/<format>.go`.
2. Implement the `parsing.Parser` interface:
   ```go
   type Parser interface {
       Format() string
       Parse(ctx context.Context, raw models.RawEvent) (*models.ParsedEvent, error)
   }
   ```
3. Register your parser in `cmd/worker/main.go`:
   ```go
   registry.Register(parsers.NewMyCustomParser())
   ```
4. Add colocated unit tests in `internal/parsing/parsers/<format>_test.go`.
5. Add sample input and expected JSON in `samples/<format>/`.

---

## 4. Local Development & Running Tests

### Start Local Dependencies (Redis + MinIO)
```bash
docker compose up -d
```

### Run Tests
```bash
go test -v ./...
```

### Start Services
```bash
# Terminal 1: Processing Worker
go run ./cmd/worker

# Terminal 2: Ingestion API
go run ./cmd/ingestion
```
