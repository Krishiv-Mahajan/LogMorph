# ULPF — Universal Log Processing Framework

ULPF (Universal Log Processing Framework) is a high-throughput, extensible platform for log ingestion, immutable raw-event archiving, format detection, parsing, normalization, validation, and downstream integration. 

Modern security and network environments generate logs from heterogeneous sources such as firewalls, WAFs, IDS/IPS systems, routers, VPNs, servers, and cloud infrastructure. These systems produce events in different formats and vendor-specific dialects (Syslog, JSON, CSV, etc.).

ULPF provides a unified processing layer between these sources and downstream systems by converting heterogeneous raw events into a standardized **Universal Event Schema**.

## Architecture

The architecture decouples ingestion from processing to handle high throughput, ensuring that all original raw data is immutably archived before it is parsed.

```text
LOG SOURCES
Firewall | WAF | IDS/IPS | VPN | Router | Server | Cloud
        |
        v
    INGESTION
   POST /ingest
        |
        v
  RAW EVENT BUFFER
   Redis Streams
    raw_events
        |
        v
 PROCESSING WORKERS
        Go
        |
        +----------------------------+
        |                            |
        v                            v
IMMUTABLE RAW EVENT STORE       PROCESSING PIPELINE
   MinIO / S3                        |
                                     v
                             FORMAT / SOURCE DETECTION
                                     |
                                     v
                             SCHEMA DRIFT ANALYSIS
                                     |
                          +----------+----------+
                          |          |          |
                       STABLE      MINOR     MAJOR /
                                              UNKNOWN
                          |          |          |
                          |          |          v
                          |          |     AI ESCALATION
                          |          |       (Planned)
                          |          |
                          +----------+----------+
                                     |
                                     v
                              PARSER REGISTRY
                                     |
                                     v
                               PARSER ENGINE
                                    Go
                                     |
                                     v
                               NORMALIZATION
                                    Go
                                     |
                                     v
                                VALIDATION
                              JSON Schema
                                     |
                           +---------+---------+
                           |                   |
                         VALID               INVALID
                           |                   |
                           v                   v
            NORMALIZED STORE (Planned)   QUARANTINE STORE (Planned)
                         |                   |
                         +---------+---------+
                                   |
                                   v
                           OUTPUT CONNECTORS
                                   |
                                   v
                         SIEM / DATA LAKE / ML
                         / OTHER CONSUMERS
```

## Core Data Lifecycle

1. **Raw Event -> Immutable Archive**: Every event received is immediately copied to MinIO/S3 as an immutable archive. The downstream processing pipeline MUST NEVER modify the archived original event.
2. **Raw Event -> Processing**: The raw event is processed, parsed, normalized, and validated.
3. **Processing -> Normalized Store / Quarantine Store**: Valid events are routed to the Normalized Store. Invalid or unparsed events are routed to the Quarantine Store. Both are persistently stored. 

### Data Quality & Quarantine: No Silent Event Loss

The Quarantine Store is a persistent data-quality storage for failed, invalid, malformed, or unparsed events. It tracks information such as: event ID, original event or reference, parser status, validation status, error type, error details, and processing metadata. It is **not** a dead-end drop mechanism.

**ULPF strictly enforces a "no silent event loss" policy.**

For example, if 100 events are received:
* 95 successfully process -> `Normalized Store`
* 5 fail validation/parsing -> `Quarantine Store`

All 100 events remain accounted for. Invalid events are not necessarily sent to every downstream consumer; instead, downstream output behavior depends on the configured output policy.

## Processing Pipeline

* **Ingestion**: A Go REST API (`POST /ingest`) receives raw events, assigns event IDs, and publishes to Redis Streams.
* **Raw Event Buffer**: Redis Streams (`raw_events`) decouples ingestion from processing and supports consumer groups/parallel workers.
* **Processing Worker**: Go workers consume raw events, coordinate the pipeline, and preserve the immutable raw copy.
* **Immutable Raw Event Store**: MinIO/S3 stores the original raw event unmodified for audit, replay, forensics, debugging, and reprocessing.
* **Format / Source Detection**: Identifies event structure/source (currently supporting Syslog, JSON, CSV).
* **Schema Drift Analysis**: Detects changes in the event structure deterministically.
* **Parser Registry**: Manages available parsers (currently an in-memory registry, planned for PostgreSQL backing).
* **Parser Engine**: Format-specific parsers built on a common Go interface.
* **Normalization**: Maps parsed data to the canonical Universal Event Schema.
* **Validation**: Enforces strict JSON Schema Validation against the normalized event.
* **Normalized Store (Planned)**: PostgreSQL store for successfully processed, analytics-ready events.
* **Quarantine Store (Planned)**: PostgreSQL store for failed/unparsed events and error tracking.
* **Output Connectors (Planned)**: Feeds SIEM, Data Lakes, and ML pipelines.

## Universal Event Schema

All supported source formats converge into a canonical Universal Event Schema. This ensures that downstream systems consume one stable contract, source-specific complexity stays inside ULPF, and schema versioning protects consumers from breaking changes.

Below is an overview of the required fields in `contracts/universal_event.schema.json` (Draft 2020-12):

* `event_id`: Unique identifier assigned at ingestion.
* `schema_version`: Must be `"1.0"`.
* `timestamp`: ISO-8601 string.
* `source`: Object detailing source `type`, `vendor`, `product`, `identifier`.
* `event`: Object detailing event `category`, `action`, `severity`.
* `raw`: The original `format` and `message`.
* `metadata`: Operational details like `parser_version` and `ingested_at`.
* *(Optional)* `network`: Details `src_ip`, `dst_ip`, ports, and `protocol`.
* *(Optional)* `user`: Details like `username`.

## Technology Stack

| Component | Technology | Status |
| :--- | :--- | :--- |
| **Ingestion API** | Go | Implemented |
| **Raw Event Buffer** | Redis Streams | Implemented |
| **Processing Worker** | Go | Implemented |
| **Immutable Raw Store** | MinIO / S3 (Memory Fallback) | Implemented |
| **Parser Engine & Registry** | Go (In-Memory Registry) | Implemented |
| **Format Parsers** | Go (Syslog, JSON, CSV) | Implemented |
| **Normalization** | Go | Implemented |
| **Validation** | JSON Schema | Implemented |
| **Normalized Store** | PostgreSQL | Planned |
| **Quarantine Store** | PostgreSQL | Planned |
| **Output Connectors** | Go | Planned |
| **AI Escalation / RAG** | Python | Planned |

## Repository Structure

```text
├── .github/          # GitHub workflows and templates
├── cmd/
│   ├── ingestion/    # REST API for receiving events
│   └── worker/       # Processing pipeline worker
├── contracts/        # JSON Schemas (universal_event, raw_event, worker_event)
├── internal/
│   ├── buffer/       # Redis Stream implementation
│   ├── detection/    # Format/Source detection & drift
│   ├── ingestion/    # Ingestion service/handlers
│   ├── models/       # Shared struct definitions
│   ├── normalization/# Mapping logic to Universal Schema
│   ├── parsing/      # Engine, Registry, and Parsers (syslog, json, csv)
│   ├── storage/      # Storage adapters (raw minio/memory)
│   ├── validation/   # JSON schema validation
│   └── worker/       # Orchestration logic
├── samples/          # Sample logs (Syslog, JSON, CSV)
├── tests/            # E2E Pipeline and integration tests
├── .env.example      # Example environment variables
├── .gitignore
├── CONTRIBUTING.md   # Contribution guidelines
├── Dockerfile.ingestion
├── Dockerfile.worker
├── docker-compose.yml# Infrastructure provisioning
├── go.mod            # Go dependencies
└── go.sum
```

## Getting Started

### Prerequisites
* Go 1.21+
* Docker & Docker Compose

### Running the System

Start the infrastructure (Redis, MinIO), ingestion API, and the processing worker:

```bash
docker-compose up --build
```

The system components will bind to:
* **Ingestion API**: `http://localhost:8080`
* **Redis**: `localhost:6379`
* **MinIO Console**: `http://localhost:9001` (minioadmin / minioadminpassword)
* **Worker**: Runs in the background consuming from Redis.

## Example Ingestion

You can send a test event to the Ingestion API. ULPF currently supports JSON, Syslog, and CSV payloads.

```bash
curl -X POST http://localhost:8080/ingest \
  -H "Content-Type: application/json" \
  -d '{
    "format": "json",
    "source": "firewall-01",
    "payload": "{\"timestamp\": \"2023-10-25T10:00:00Z\", \"src_ip\": \"192.168.1.100\", \"action\": \"deny\", \"dst_port\": 443}"
  }'
```

You will receive an HTTP 202 Accepted response with the assigned `event_id`:
```json
{
  "status": "accepted",
  "event_id": "msg_01H..."
}
```

The worker will automatically pull this event from the `raw_events` Redis stream, save the raw payload to MinIO, and process it through the pipeline.

## Testing

Run the full End-to-End test suite to verify pipeline convergence for all supported formats:

```bash
go test -v ./tests/...
```

You can also run unit tests for internal packages:
```bash
go test -v ./internal/...
```

## Design Principles

* **Immutable Raw Data**: The raw payload is written to an immutable side branch prior to any processing.
* **No Silent Event Loss**: All events (valid or invalid) must end up in a persistent store.
* **Decoupled Ingestion/Processing**: Redis Streams ensure spikes in log volume don't overwhelm parsers.
* **Canonical Events**: Downstream consumers only ever see the Universal Event Schema.
* **Contract-Driven Validation**: All events are validated via JSON schema before storage.
* **Fault Isolation**: Parser failures do not crash the worker or lose the event (routed to quarantine).
* **Intelligence Outside Critical Path**: AI/ML inference (planned) is reserved for asynchronous schema drift analysis or quarantine escalation, keeping the Go pipeline fast.

## Roadmap

Future capabilities planned for ULPF:
* **Persistent Stores**: Implementation of PostgreSQL-backed Normalized Store, Quarantine Store, and Parser Registry.
* **Output Connectors**: Connectors for leading SIEMs, Data Lakes, and Webhooks.
* **Additional Parsers**: Out-of-the-box support for CEF, LEEF, and popular vendor integrations.
* **Intelligent Drift Analysis**: ML-assisted detection of minor format changes.
* **AI Escalation**: Python-based local LLM/RAG integration to automatically generate parsers for unknown log formats found in the Quarantine Store.
* **Horizontal Scaling**: Production hardening for clustered Redis and scaled worker deployments.

## Project Vision

ULPF serves as a universal, high-throughput processing layer between the chaotic ecosystem of heterogeneous log sources and the structured demands of downstream security systems. By maintaining strict schema contracts and guaranteeing zero silent event loss, ULPF enables organizations to adapt to changing infrastructure without continually rewriting downstream SIEM or ML integrations.