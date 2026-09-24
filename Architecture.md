# Architecture

## System Overview

The application is a web-based CTI investigation platform. The browser is never a direct Group-IB API client. Group-IB credentials and provider communication remain behind the backend security boundary.

```
┌───────────────────────────────────────────────────────────────────┐
│                         WEB BROWSER                               │
│ React / Next.js / TypeScript / Tailwind                           │
│ Dashboard │ Search │ New │ Old │ Re-seen │ Repeat │ Investigation │
│ Actors │ Stealers │ Leak Sources │ References │ Reports           │
└──────────────────────────────┬────────────────────────────────────┘
                               │ HTTPS
                               ▼
┌───────────────────────────────────────────────────────────────────┐
│                       FASTAPI BACKEND                              │
│ Auth │ RBAC │ Validation │ REST API │ Audit │ Policy Enforcement  │
└───────────────┬───────────────────────┬───────────────────────────┘
                │                       │
                │                       ▼
                │              ┌──────────────────────┐
                │              │ Redis / Job Queue    │
                │              │ Cache │ Rate State   │
                │              └──────────┬───────────┘
                │                         │
                │                         ▼
                │              ┌──────────────────────┐
                │              │ Ingestion Workers    │
                │              │ Group-IB Retrieval   │
                │              │ Normalize / Classify │
                │              └──────────┬───────────┘
                │                         │
                ▼                         ▼
┌───────────────────────────────────────────────────────────────────┐
│                         POSTGRESQL                                │
│ Findings │ Observations │ Actors │ Sources │ References           │
│ Stealers │ Evidence Metadata │ Audit │ Ingestion State             │
└──────────────────────────────┬────────────────────────────────────┘
                               │
                               ▼
                    ┌─────────────────────────┐
                    │ Raw Evidence Boundary   │
                    │ JSONB / Object Storage  │
                    │ Integrity / Retention   │
                    └─────────────────────────┘

                               │
                               ▼
                    ┌─────────────────────────┐
                    │ Report Service          │
                    │ Executive + Technical   │
                    │ PDF / Evidence Summary  │
                    └─────────────────────────┘
```

## Service Boundaries

### Frontend — Next.js
Responsibilities:
- authentication/session presentation
- dashboard
- search/filter UI
- finding lifecycle views
- investigation detail
- attacker/stealer/source/reference views
- evidence display with appropriate redaction
- report request/download
- client-side validation only as a usability layer

The frontend must never contain Group-IB API credentials or call Group-IB directly.

### Backend — FastAPI
Responsibilities:
- authentication and authorization
- RBAC
- request validation
- application/service contracts
- investigation APIs
- ingestion orchestration
- audit logging
- report orchestration
- secret access boundary
- safe error handling

The backend is the authoritative application policy boundary.

### Ingestion Workers
Responsibilities:
- provider retrieval
- pagination/incremental retrieval
- retry/backoff
- response schema validation
- raw evidence capture
- canonical normalization
- deterministic fingerprinting
- idempotent persistence
- lifecycle classification
- ingestion checkpoint management

Long-running provider retrieval must not block synchronous HTTP requests.

### Redis
Responsibilities:
- worker queue
- short-lived cache where justified
- rate-limit coordination
- job state/locks where required

Redis is not the system of record.

### PostgreSQL
Responsibilities:
- normalized intelligence
- provider identities
- observations
- lifecycle state
- attacker/source/stealer relationships
- audit metadata
- ingestion checkpoints
- report metadata

Database constraints and transactions are required for idempotency.

### Evidence Storage
Responsibilities:
- preserve raw provider payloads when retention is authorized
- maintain integrity metadata
- support evidence replay/reprocessing
- enforce retention and access controls

Raw evidence must not become an uncontrolled dump of sensitive credentials/cookies.

## Core Data Model Direction

```
Provider Finding
    │
    ├── provider_record
    │
    ├── compromise_identity
    │
    ├── observations
    │      ├── first observed
    │      ├── last observed
    │      └── event identity
    │
    ├── account / domain
    ├── exposure
    ├── infostealer
    ├── attacker / attribution
    ├── leak source / collection
    ├── references
    └── evidence
```

The model must not collapse these identities into one timestamp-based hash.

## Lifecycle Classification

Classification is based on provider evidence plus durable local history.

### NEW
A normalized compromise/provider finding that has not previously been observed by this platform and satisfies the configured newness policy.

### OLD / HISTORICAL
A known compromise whose underlying compromise is older than the configured newness policy and is not represented as a newly discovered underlying compromise.

### RESEEN / RECYCLED
A known underlying compromise that is observed again, updated, or returned by the provider after prior local ingestion.

This category exists specifically to prevent old compromises repeatedly returned by the provider from becoming false "new" alerts.

### REPEAT
An already processed provider observation/event. It must be idempotent and must not create a duplicate logical finding.

Classification must be auditable: store the reason and relevant timestamps/identity references used by the classifier.

## Intelligence Provenance Model

Where the provider exposes the data, a finding may link to:

- Group-IB endpoint
- provider record ID
- attacker/threat actor
- campaign
- stealer family/build
- HWID
- victim IP
- operating system
- target URL/service
- leak source
- collection/dump
- marketplace/forum/channel reference
- publication date
- first/last observation
- related event identifiers
- external/source references

The system must distinguish **provider-supplied attribution** from application inference. Unavailable fields remain null.

## Data Flow

```
User
  ↓
Next.js
  ↓ HTTPS
FastAPI
  ↓
Authorization + Validation
  ↓
Service Layer
  ├──────────────→ PostgreSQL (read/search)
  │
  └──────────────→ Redis Job Queue
                         ↓
                    Ingestion Worker
                         ↓
                    Group-IB API
                         ↓
                    Raw Evidence
                         ↓
                    Schema Validation
                         ↓
                    Canonical Normalization
                         ↓
                    Identity / Fingerprinting
                         ↓
                    Transactional Upsert
                         ↓
                    Lifecycle Classification
                         ↓
                    PostgreSQL
                         ↓
                    FastAPI
                         ↓
                    Next.js Investigation UI
```

## Recommended Backend Modules

```
backend/
├── app/
│   ├── main.py
│   ├── api/
│   ├── auth/
│   ├── core/
│   ├── models/
│   ├── schemas/
│   ├── repositories/
│   ├── services/
│   ├── providers/
│   │   └── groupib/
│   ├── ingestion/
│   ├── classification/
│   ├── evidence/
│   ├── reporting/
│   └── audit/
└── tests/
```

## Recommended Frontend Modules

```
frontend/
├── app/
│   ├── dashboard/
│   ├── findings/
│   ├── infostealers/
│   ├── actors/
│   ├── sources/
│   ├── references/
│   ├── reports/
│   └── settings/
├── components/
├── features/
├── lib/
├── hooks/
├── types/
└── tests/
```

## API Direction

Example application endpoints:

```
POST   /api/v1/ingestions
GET    /api/v1/ingestions/{id}
GET    /api/v1/findings
GET    /api/v1/findings/{id}
GET    /api/v1/findings/{id}/evidence
GET    /api/v1/infostealers
GET    /api/v1/actors
GET    /api/v1/sources
GET    /api/v1/references
GET    /api/v1/dashboard/metrics
POST   /api/v1/reports
GET    /api/v1/reports/{id}
```

These are **application API contracts**, not Group-IB provider endpoints. Provider endpoint names and authentication must be verified before implementation.

## Security Architecture

```
Browser
  │
  │ No Group-IB secret
  ▼
Authentication
  │
  ▼
RBAC / Authorization
  │
  ▼
FastAPI
  │
  ├── Input validation
  ├── Audit
  ├── Rate limiting
  └── Service policy
       │
       ├── PostgreSQL
       ├── Redis
       └── Group-IB credential boundary
```

Sensitive intelligence such as plaintext credentials and session cookies requires explicit access control, redaction policy and retention controls.

## Reporting Architecture

Reports are generated from normalized application data rather than directly from browser state.

```
PostgreSQL
   ↓
Report Service
   ↓
Redaction / Authorization Check
   ↓
PDF Generator
   ↓
Controlled Report Artifact
```

Reports must include provenance and timestamps while avoiding unnecessary exposure of secrets.

## Deployment

### Local Development
```
Docker Compose
├── frontend
├── backend
├── worker
├── postgres
└── redis
```

### Production Direction
- HTTPS termination
- secure application secrets
- private PostgreSQL
- private Redis
- least-privilege service accounts
- structured logs with secret redaction
- health/readiness checks
- database migration management
- backup/restore validation
- controlled evidence retention

## Validation Gates

### Gate 1 — Web Architecture
Verify service boundaries and dependency direction.

### Gate 2 — Group-IB API Contract
Verify authentication, endpoints, parameters, pagination/incremental retrieval, status/error behavior and response schemas.

### Gate 3 — Ingestion Integrity
Verify raw evidence → schema validation → normalization → fingerprint → transactional persistence.

### Gate 4 — Lifecycle
Verify NEW / OLD / RESEEN / REPEAT against repeat retrievals and persisted history.

### Gate 5 — Backend API
Verify authentication, RBAC, validation, pagination, filtering, error handling and audit behavior.

### Gate 6 — Frontend
Verify dashboards, investigation views, filtering, evidence access and safe redaction.

### Gate 7 — Reporting
Verify executive/technical reports, authorization and redaction.

### Gate 8 — End-to-End
Verify Group-IB → ingestion → PostgreSQL → FastAPI → Next.js → report.

## Current Migration Note
The repository currently contains the original PyQt6 desktop baseline. That code is retained only as historical implementation context during the migration. New architecture work must follow this web application specification. Desktop-specific UI code must not be treated as the target architecture.
