# ULPF — Universal Log Processing Framework

ULPF (**Universal Log Processing Framework**) is an extensible, high-throughput log ingestion, raw archiving, and normalization platform built for security operations and network monitoring.

Heterogeneous devices (firewalls, routers, servers, cloud infrastructure) produce logs in diverse dialects (BSD Syslog, JSON, CSV, CEF, etc.). ULPF decouples downstream analytic engines and security workers from upstream log diversity by buffering raw events, storing an immutable copy in object storage, and normalizing logs into a canonical **Universal Event Schema**.

---

## 1. Target Architecture (Source of Truth)

```text
                         LOG SOURCES
        Firewall | WAF | IDS/IPS | VPN | Router | etc.
                              │
                              ▼
                     ┌────────────────┐
                     │   INGESTION    │
                     │  (POST /ingest)│
                     └───────┬────────┘
                             │
                             ▼
                     ┌────────────────┐
                     │ RAW EVENT      │
                     │ BUFFER         │
                     │ Redis Streams  │
                     │  (raw_events)  │
                     └───────┬────────┘
                             │
                             ▼
                ┌────────────────────────┐
                │   PROCESSING WORKERS   │
                │          GO            │
                └───────────┬────────────┘
                            │
              ┌─────────────┴──────────────┐
              │                            │
              ▼                            │
       ┌──────────────┐                    │
       │ RAW EVENT    │                    │
       │ STORE        │                    │
       │ MinIO / S3   │                    │
       │ IMMUTABLE    │                    │
       └──────────────┘                    │
                                           │
                                           ▼
                              ┌────────────────────────┐
                              │ FORMAT / SOURCE        │
                              │ DETECTION              │
                              │ GO                     │
                              └────────────┬───────────┘
                                           │
                                           ▼
                              ┌────────────────────────┐
                              │ SCHEMA DRIFT ANALYSIS  │
                              │                        │
                              │ MVP: basic/placeholder │
                              │ Future: intelligent    │
                              └────────────┬───────────┘
                                           │
                              ┌────────────┼────────────┐
                              │            │            │
                           STABLE        MINOR       MAJOR/
                                         DRIFT       UNKNOWN
                              │            │            │
                              │            │            ▼
                              │            │     ┌──────────────┐
                              │            │     │ AI ESCALATION│
                              │            │     │   PYTHON     │
                              │            │     │ Future phase │
                              │            │     └──────────────┘
                              │            │
                              │            ▼
                              │     Minor Drift Handler
                              │
                              └────────────┬───────────────
                                           ▼
                              ┌────────────────────────┐
                              │    PARSER REGISTRY     │
                              │      PostgreSQL        │
                              │      Future phase      │
                              └────────────┬───────────┘
                                           │
                                           ▼
                              ┌────────────────────────┐
                              │     PARSER ENGINE      │
                              │          GO            │
                              └────────────┬───────────┘
                                           │
                                           ▼
                              ┌────────────────────────┐
                              │     NORMALIZATION      │
                              │          GO            │
                              └────────────┬───────────┘
                                           │
                                           ▼
                              ┌────────────────────────┐
                              │       VALIDATION       │
                              │     JSON Schema        │
                              └────────────┬───────────┘
                                           │
                                  ┌────────┴────────┐
                                  ▼                 ▼
                               VALID             INVALID
                                  │                 │
                                  ▼                 ▼
                         Normalized Store      Quarantine
                           PostgreSQL           PostgreSQL
                              │
                              ▼
                       Output Connectors
```

> [!IMPORTANT]
> **Immutable Raw Event Store**: The Raw Event Store (MinIO/S3) is an immutable side-branch. The original raw event is copied to MinIO and is **never** modified by the downstream processing pipeline.

---

## 2. Monday MVP Scope

The Monday MVP demonstrates the complete vertical slice:

```text
Syslog ──┐
JSON ────┼──→ Ingestion ──→ Redis raw_events ──→ Worker ──┬──→ MinIO (Immutable Raw Copy)
CSV ─────┘                                                │
                                                          └──→ Detection ──→ Drift Check ──→ Parser Engine ──→ Normalization ──→ Validation ──→ Universal Event
```

### What is implemented in the MVP:
- REST Ingestion API (`POST /ingest`)
- Redis Streams Raw Buffer (`raw_events`)
- MinIO / S3 Immutable Raw Event Store (`raw-events/{event_id}.json`)
- Deterministic Format / Source Detector (Syslog, JSON, CSV)
- Drift Detector interface (MVP deterministic check)
- Parser Registry & Parser Engine (Syslog, JSON, CSV)
- Normalizer generating canonical Universal Event v1.0
- JSON Schema Draft 2020-12 Validator (`universal_event.schema.json`)
- Processing Worker with Consumer Group management

---

## 3. Technology Split

- **Go**: High-throughput ingestion, Redis stream buffering, processing workers, format detection, parser engine, normalization, schema validation, and storage connectors.
- **Python (Future Phase)**: Reserved for the intelligence layer: AI escalation, RAG, embeddings, local LLMs, and automated parser generation.

---

## 4. Repository Structure

```text
LogMorph/
├── cmd/
│   ├── ingestion/
│   │   └── main.go                 # Ingestion HTTP service entrypoint
│   └── worker/
│       └── main.go                 # Processing worker entrypoint
│
├── contracts/
│   ├── raw_event.schema.json       # Inbound RawEvent contract schema
│   ├── universal_event.schema.json # UniversalEvent JSON Schema (v1.0)
│   └── worker_event.schema.json    # Worker transport envelope schema
│
├── internal/
│   ├── buffer/
│   │   └── redis.go                # Redis Streams raw_events buffer
│   ├── detection/
│   │   ├── detector.go             # Format & source detection
│   │   ├── detector_test.go
│   │   ├── drift.go                # Drift detector interface & MVP analyzer
│   │   └── drift_test.go
│   ├── ingestion/
│   │   ├── handler.go              # HTTP handlers for /ingest & /health
│   │   ├── handler_test.go
│   │   └── service.go              # Ingestion business logic
│   ├── models/
│   │   └── event.go                # Shared domain structs
│   ├── normalization/
│   │   ├── normalizer.go           # Canonical field normalizer
│   │   └── normalizer_test.go
│   ├── parsing/
│   │   ├── engine.go               # Parser engine
│   │   ├── parser.go               # Parser interface contract
│   │   ├── registry.go             # Thread-safe parser registry
│   │   └── parsers/
│   │       ├── syslog.go           # Syslog firewall parser
│   │       ├── syslog_test.go
│   │       ├── json.go             # JSON firewall parser
│   │       ├── json_test.go
│   │       ├── csv.go              # CSV firewall parser
│   │       └── csv_test.go
│   ├── storage/
│   │   └── raw/
│   │       ├── store.go            # RawEventStore interface & memory store
│   │       ├── minio.go            # MinIO / S3 immutable store
│   │       └── store_test.go
│   ├── validation/
│   │   ├── universal_event.schema.json
│   │   ├── validator.go            # JSON Schema validator
│   │   └── validator_test.go
│   └── worker/
│       ├── worker.go               # Processing worker loop
│       └── worker_test.go
│
├── samples/
│   ├── syslog/                     # Sample log & expected Universal Event
│   ├── json/
│   └── csv/
│
├── tests/
│   └── pipeline_test.go            # End-to-end integration tests
│
├── docker-compose.yml              # Local Redis + MinIO services
├── .env.example                    # Environment variable configuration
├── CONTRIBUTING.md                 # Team guidelines & package boundaries
├── go.mod
├── go.sum
└── README.md
```

---

## 5. Quickstart Guide

### Prerequisites
- Go 1.22+ installed
- Docker & Docker Compose

### 1. Start Local Infrastructure (Redis + MinIO)
```bash
docker compose up -d
```
Verify containers are healthy:
```bash
docker compose ps
```
- **Redis**: `localhost:6379`
- **MinIO API**: `localhost:9000`
- **MinIO Console**: `http://localhost:9001` (User: `minioadmin` / Password: `minioadminpassword`)

### 2. Start Processing Worker (Terminal 1)
```bash
go run ./cmd/worker
```

### 3. Start Ingestion API (Terminal 2)
```bash
go run ./cmd/ingestion
```

---

## 6. Example Ingestion Requests

### Syslog Ingestion
```bash
curl -i -X POST http://localhost:8080/ingest \
  -H "Content-Type: application/json" \
  -d '{
    "format": "syslog",
    "source": "firewall-01",
    "payload": "Aug 28 18:30:12 firewall01 DENY TCP SRC=192.168.1.20:54321 DST=10.0.0.15:443"
  }'
```

Response:
```json
{
  "event_id": "evt_b8c8d8a1-8d2b-4e12-a7f4-3d1fa82d02c6",
  "status": "accepted"
}
```

### JSON Ingestion
```bash
curl -i -X POST http://localhost:8080/ingest \
  -H "Content-Type: application/json" \
  -d '{
    "format": "json",
    "source": "firewall-02",
    "payload": "{\"timestamp\":\"2026-08-28T18:30:12Z\",\"firewall\":{\"action\":\"deny\",\"protocol\":\"TCP\"},\"network\":{\"source\":{\"ip\":\"192.168.1.20\",\"port\":54321},\"destination\":{\"ip\":\"10.0.0.15\",\"port\":443}}}"
  }'
```

### CSV Ingestion (Auto-detected Format)
```bash
curl -i -X POST http://localhost:8080/ingest \
  -H "Content-Type: application/json" \
  -d '{
    "payload": "timestamp,action,protocol,src_ip,src_port,dst_ip,dst_port\n2026-08-28T18:30:12Z,deny,TCP,192.168.1.20,54321,10.0.0.15,443"
  }'
```

---

## 7. Normalized Universal Event Output

All formats converge to the canonical Universal Event schema:

```json
{
  "event_id": "evt_b8c8d8a1-8d2b-4e12-a7f4-3d1fa82d02c6",
  "schema_version": "1.0",
  "timestamp": "2026-08-28T18:30:12Z",
  "source": {
    "type": "firewall",
    "vendor": "generic",
    "product": "syslog-firewall",
    "identifier": "firewall-01"
  },
  "event": {
    "category": "network",
    "action": "deny",
    "severity": "high"
  },
  "network": {
    "src_ip": "192.168.1.20",
    "src_port": 54321,
    "dst_ip": "10.0.0.15",
    "dst_port": 443,
    "protocol": "TCP"
  },
  "user": {
    "username": null
  },
  "raw": {
    "format": "syslog",
    "message": "Aug 28 18:30:12 firewall01 DENY TCP SRC=192.168.1.20:54321 DST=10.0.0.15:443"
  },
  "metadata": {
    "parser_version": "1.0",
    "ingested_at": "2026-08-29T00:15:00Z"
  }
}
```

The worker outputs:
```text
[Worker] Processed event evt_b8c8d8a1-8d2b-4e12-a7f4-3d1fa82d02c6 | format: syslog | action: deny | net: 192.168.1.20:54321 -> 10.0.0.15:443 (proto: TCP) | timestamp: 2026-08-28T18:30:12Z
```

---

## 8. Running Tests

Run all unit and integration tests:
```bash
go test -v ./...
```
