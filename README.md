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
* **Schema Drift Analysis**: Compares an incoming payload against the contract the source registry holds for that source, and classifies the difference.
* **Source Registry**: Maps a source fingerprint to the parser and mapping version that owns it, with an append-only version chain in PostgreSQL.
* **Parser Registry**: Manages available parsers and their declared field contracts.
* **Parser Engine**: Format-specific parsers built on a common Go interface.
* **Normalization**: Maps parsed data to the canonical Universal Event Schema.
* **Validation**: Enforces strict JSON Schema Validation against the normalized event.
* **Normalized Store**: PostgreSQL store for successfully processed, analytics-ready events.
* **Quarantine Store**: PostgreSQL store for failed/unparsed events and error tracking.
* **Output Connectors (Planned)**: Feeds SIEM, Data Lakes, and ML pipelines.

### Source Registry & Minor Drift

Every event is resolved to a **source fingerprint** built from transport
identity (format + source hint + source type). Critically, the fingerprint is
derived *before* parsing and never from field names, so a source that changes
its schema is still recognised as the same source drifting.

The registry holds an append-only chain of **mapping versions** per source. The
first event from a source records the contract its parser declares as v1.

When a payload differs from the active contract, the drift engine classifies the
difference:

| Change | Verdict | Action |
| :--- | :--- | :--- |
| Extra scalar field | `minor_drift` | Recorded as an optional, unbound field; new mapping version |
| Declared alias used as a synonym | `stable` | No version change; the contract already covers it |
| Optional field absent | `stable` | Absence of an optional field is not drift |
| Required field absent | `major_drift` | **Not** adapted; escalated |
| Incompatible type change | `major_drift` | **Not** adapted; escalated |
| New nested structure | `major_drift` | **Not** adapted; escalated |
| Two names, one target, different values | `major_drift` | **Not** adapted; escalated |

Auto-adaptation is deliberately asymmetric: adding a field cannot change the
meaning of fields already mapped, so it is safe to record. Anything that could
change meaning is escalated instead — an escalated event is still parsed with the
last known-good mapping, so it is never dropped, but its `drift_status` records
that the source needs review. No AI or human review step is implemented yet.

Aliases are declared in the contract and applied after parsing by the alias
binder, which only fills attributes the parser left empty and never binds a
field whose meaning is not declared.

### Failure Classification & Retry Semantics

Every event ends a processing attempt with exactly one outcome, and the Redis
ACK/retry decision follows from it:

| Outcome | Meaning | Redis behaviour |
| :--- | :--- | :--- |
| `SUCCESS` | Parsed, normalized, validated, and persisted. | Marked done, ACKed. |
| `QUARANTINED` | Deterministic failure (malformed payload, no parser, schema violation). | Written to `quarantined_events`, marked done, ACKed. |
| `RETRYABLE_FAILURE` | Infrastructure failure (MinIO, PostgreSQL). | Lock released, **not** ACKed — XAUTOCLAIM redelivers it. |

Classification is stage-driven: parsing, normalization, and validation are
deterministic, so their failures are permanent and quarantined immediately.
Raw-store and persistence failures depend on external systems and are retried,
up to `WORKER_MAX_ATTEMPTS` attempts, after which the event is quarantined as
`max_attempts_exceeded` rather than retried forever. A quarantined event is
never left in Redis, and a retryable failure is never quarantined.

Persistence is idempotent at the database level (`PRIMARY KEY (event_id)` with
`ON CONFLICT DO NOTHING`), so a retried or re-delivered event cannot create a
second normalized row. Duplicate-suppression is independent of the Redis
done-marker, so it holds across restarts and after the marker expires.

### Provenance

Every stored event carries the chain that produced it:

```
raw object (MinIO)  ->  event_id  ->  parser_id + parser_version
                                  ->  mapping_id + mapping_version
                                  ->  source_fingerprint + drift_status
```

The provenance is written both into the event's `metadata` block and into
columns on `normalized_events` / `quarantined_events`, so stored events join
directly to `source_registry`. Because mapping versions are append-only and
superseded rather than edited, an event processed under v1 remains explainable
after the source has moved to v3.

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
| **Normalized Store** | PostgreSQL | Implemented |
| **Quarantine Store** | PostgreSQL | Implemented |
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
│   ├── contract/     # Declarative field contracts (the "mapping" model)
│   ├── detection/    # Format/Source detection & format-level drift
│   ├── drift/        # Schema observation, drift classification, alias binding
│   ├── failure/      # Error classification (permanent vs retryable)
│   ├── ingestion/    # Ingestion service/handlers
│   ├── models/       # Shared struct definitions
│   ├── normalization/# Mapping logic to Universal Schema
│   ├── parsing/      # Engine, parser registry, and parsers (syslog, json, csv)
│   │   └── parsers/  #   Parser implementations + declared contracts
│   ├── registry/     # Source registry: fingerprint -> parser/mapping versions
│   ├── storage/      # Storage adapters
│   │   ├── normalized/#   PostgreSQL normalized event store (+ memory)
│   │   ├── postgres/  #    Connection pool & embedded migrations
│   │   ├── quarantine/#   PostgreSQL dead-letter store (+ memory)
│   │   └── raw/       #   Immutable raw store (minio/memory)
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

Start the infrastructure (Redis, MinIO, PostgreSQL), ingestion API, and the processing worker:

```bash
docker-compose up --build
```

The worker applies the database migrations at startup, so no manual schema
setup is required.

The system components will bind to:
* **Ingestion API**: `http://localhost:8080`
* **Redis**: `localhost:6379`
* **MinIO Console**: `http://localhost:9001` (minioadmin / minioadminpassword)
* **PostgreSQL**: `localhost:5432` (logmorph / logmorph — local defaults, override via `.env`)
* **Worker**: Runs in the background consuming from Redis.

All credentials are read from the environment; see `.env.example`.

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

Validated events land in PostgreSQL:

```bash
docker-compose exec postgres psql -U logmorph -d logmorph \
  -c "SELECT event_id, event_action, src_ip, raw_object_key FROM normalized_events"
```

Events that fail permanently land in the quarantine store with the failure
stage, failure type, error, attempt count, and a reference to the raw object:

```bash
docker-compose exec postgres psql -U logmorph -d logmorph \
  -c "SELECT event_id, failure_stage, failure_type, error_message FROM quarantined_events"
```

## Testing

Run the full End-to-End test suite to verify pipeline convergence for all supported formats:

```bash
go test -v ./tests/...
```

You can also run unit tests for internal packages:
```bash
go test -v ./internal/...
```

The PostgreSQL store tests are integration tests: they skip unless a database is
provided, so the default run needs no services.

```bash
TEST_POSTGRES_DSN="postgres://logmorph:logmorph@localhost:5432/logmorph?sslmode=disable" \
  go test -v ./internal/storage/...
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