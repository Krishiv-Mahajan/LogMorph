# ULPF — Universal Log Processing Framework

ULPF (**Universal Log Processing Framework**) is an extensible, high-throughput log ingestion and normalization platform designed for security operations and network monitoring.

Heterogeneous devices (firewalls, routers, servers, cloud infrastructure) produce logs in wildly varying formats (BSD Syslog, JSON, CSV, CEF, etc.). ULPF decouples downstream analytic engines and security workers from upstream log diversity by converting raw logs into a standardized **Universal Event Schema**.

---

## 1. Why the Universal Event Schema Exists

Security analysis and SIEM engines should not need individual code paths for each vendor log dialect. By defining a canonical **Universal Event Schema (v1.0)**:
- **Downstream Decoupling**: Downstream consumers (anomaly detectors, SIEMs, correlation workers) read a single structured contract regardless of source.
- **Format-Drift Resilience**: If a firewall upgrades its firmware and changes key formats, only the specific parser/mapping layer needs updating—downstream workers remain untouched.
- **Auditability**: The original raw message and ingestion metadata are always preserved in the normalized event.

---

## 2. Architecture

```text
                    ┌─────────────────┐
                    │   Raw Log       │
                    │ Syslog/JSON/CSV │
                    └────────┬────────┘
                             │
                             ▼
                    ┌─────────────────┐
                    │ Ingestion API   │
                    │  (POST /ingest) │
                    └────────┬────────┘
                             │
                             ▼
                    ┌─────────────────┐
                    │ Format Detection│
                    └────────┬────────┘
                             │
                             ▼
                    ┌─────────────────┐
                    │ Parser Registry │
                    │ Syslog/JSON/CSV │
                    └────────┬────────┘
                             │
                             ▼
                    ┌─────────────────┐
                    │  Normalization  │
                    │ Universal Event │
                    └────────┬────────┘
                             │
                             ▼
                    ┌─────────────────┐
                    │ JSON Validation │
                    │ (Schema v1.0)   │
                    └────────┬────────┘
                             │
                             ▼
                    ┌─────────────────┐
                    │  Redis Streams  │
                    │normalized_events│
                    └────────┬────────┘
                             │
                             ▼
                    ┌─────────────────┐
                    │ Processing      │
                    │ Go Worker       │
                    └─────────────────┘
```

---

## 3. Repository Structure

```text
LogMorph/
├── cmd/
│   ├── ingestion/
│   │   └── main.go                 # Ingestion HTTP service entrypoint
│   └── worker/
│       └── main.go                 # Stream consumer worker entrypoint
│
├── contracts/
│   ├── universal_event.schema.json # Canonical JSON Schema v1.0
│   ├── raw_event.schema.json       # Inbound RawEvent contract
│   └── worker_event.schema.json    # Redis transport envelope contract
│
├── internal/
│   ├── detection/
│   │   ├── detector.go             # Deterministic format detector
│   │   └── detector_test.go        # Detector unit tests
│   ├── ingestion/
│   │   └── handler.go              # HTTP handlers for /ingest & /health
│   ├── models/
│   │   └── event.go                # Domain types & schema structs
│   ├── normalization/
│   │   ├── normalizer.go           # Pipeline orchestration
│   │   ├── normalizer_test.go      # Pipeline tests
│   │   ├── parser.go               # Parser interface contract
│   │   ├── registry.go             # Thread-safe parser registry
│   │   └── parsers/
│   │       ├── syslog.go           # Syslog security parser
│   │       ├── syslog_test.go      # Syslog parser tests
│   │       ├── json.go             # JSON security parser
│   │       ├── json_test.go        # JSON parser tests
│   │       ├── csv.go              # CSV security parser
│   │       └── csv_test.go         # CSV parser tests
│   ├── redis/
│   │   └── stream.go               # Redis Streams client wrapper
│   ├── validation/
│   │   ├── universal_event.schema.json
│   │   ├── validator.go            # JSON Schema validator engine
│   │   └── validator_test.go       # Validator tests
│   └── worker/
│       └── worker.go               # Redis consumer group worker loop
│
├── samples/
│   ├── syslog/
│   │   ├── sample.log
│   │   └── expected.json
│   ├── json/
│   │   ├── sample.json
│   │   └── expected.json
│   └── csv/
│       ├── sample.csv
│       └── expected.json
│
├── tests/
│   └── pipeline_test.go            # End-to-end integration tests
│
├── docker-compose.yml              # Local Redis service
├── go.mod
├── go.sum
└── README.md
```

---

## 4. Technology Stack

- **Backend & Processing**: Go 1.26
- **Event Transport**: Redis 7 Streams (`normalized_events`)
- **Schema Validation**: JSON Schema Draft 2020-12 via `github.com/santhosh-tekuri/jsonschema/v5`
- **HTTP Engine**: Go `net/http` standard library
- **Local Infrastructure**: Docker Compose

---

## 5. Getting Started

### Prerequisites
- Go 1.22+ installed
- Docker & Docker Compose installed

### Step 1: Install Go Dependencies
```bash
go mod download
```

### Step 2: Start Redis
```bash
docker compose up -d
```

Verify Redis is healthy:
```bash
docker compose ps
```

### Step 3: Start the Ingestion Service
```bash
go run cmd/ingestion/main.go
```
The ingestion API will start on `http://localhost:8080`.

### Step 4: Start the Processing Worker (In a Separate Terminal)
```bash
go run cmd/worker/main.go
```
The worker connects to Redis, creates the consumer group (`ulpf-worker-group`), and listens on the `normalized_events` stream.

---

## 6. Usage & Example Requests

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
  "event_id": "evt_4b4f3bda-69a4-4ca8-9279-3d1fa82d02c6",
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

## 7. Example Normalized Universal Event

All 3 input formats above normalize into the exact same canonical structure:

```json
{
  "event_id": "evt_4b4f3bda-69a4-4ca8-9279-3d1fa82d02c6",
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
    "ingested_at": "2026-08-28T23:25:00Z"
  }
}
```

The worker outputs:
```text
[Worker] Processed event evt_4b4f3bda-69a4-4ca8-9279-3d1fa82d02c6 | format: syslog | action: deny | net: 192.168.1.20:54321 -> 10.0.0.15:443 (proto: TCP) | timestamp: 2026-08-28T18:30:12Z
```

---

## 8. Running Tests

Run all unit and integration tests:
```bash
go test -v ./...
```

---

## 9. Current Limitations & Scope

- **MVP Scope**: Currently focuses on network/firewall security logs (Syslog, JSON, CSV).
- **In-Memory Buffer in Ingestion**: Ingestion service normalizes and validates synchronously before publishing to Redis.
- **No Heavy SIEM/ML Engine**: Built without AI, ML, correlation engines, or authentication layers to keep the core clean and predictable.

---

## 10. Future Extension Points

- **Additional Parsers**: Add CEF (Common Event Format), LEEF, Windows Event Log (EVTX), and CloudTrail parsers by implementing the `normalization.Parser` interface and registering with `registry.Register()`.
- **Dead Letter Queue (DLQ)**: Route validation failures to a dedicated `quarantine_events` Redis stream.
- **Microservice Decoupling**: Deploy ingestion, parser nodes, and analytics workers as independently scalable Go microservices.
- **Plug-in Storage**: Add OpenSearch / ClickHouse sink workers consuming from `normalized_events`.
