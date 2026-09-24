# Group-IB Threat Intelligence Web Application

Production-oriented web CTI investigation platform for Group-IB TI&A intelligence.

## Purpose

The platform ingests Group-IB threat intelligence and turns provider observations into a durable, searchable intelligence dataset.

It is designed to distinguish:

- **NEW** findings
- **OLD / HISTORICAL** compromises
- **RESEEN / RECYCLED** compromises repeatedly observed by the provider
- **REPEAT** observations already processed by the platform

It also preserves structured provenance for infostealers, attackers/attribution, leak sources, collections and dark-web references when those fields are explicitly supplied by Group-IB.

## Target Stack

- **Frontend:** Next.js / React / TypeScript / Tailwind CSS
- **Backend:** FastAPI / Python
- **Workers:** Redis-backed asynchronous ingestion
- **Database:** PostgreSQL
- **Evidence:** controlled raw JSON/evidence boundary
- **Reporting:** server-side PDF generation
- **Deployment:** Docker Compose locally, containerized production path

## Security Model

The browser never communicates directly with Group-IB.

Group-IB credentials remain server-side and are protected by the backend secret boundary. Authentication, RBAC, validation, audit and redaction are enforced by the application.

Sensitive intelligence such as plaintext passwords and session cookies is treated as restricted evidence.

## Core Workflow

```
Group-IB
   ↓
Provider Retrieval
   ↓
Raw Evidence
   ↓
Schema Validation
   ↓
Canonical Normalization
   ↓
Identity / Fingerprinting
   ↓
Transactional Persistence
   ↓
Lifecycle Classification
   ├── NEW
   ├── OLD / HISTORICAL
   ├── RESEEN / RECYCLED
   └── REPEAT
   ↓
FastAPI
   ↓
Next.js Investigation UI
   ↓
Reporting
```

## Investigation Areas

### Dashboard
- total findings
- new findings
- historical findings
- re-seen/recycled findings
- infostealer infections
- active session indicators
- source/actor/stealer summaries

### Findings
Searchable and filterable compromised-account intelligence with timeline, exposure, provenance and lifecycle status.

### Infostealers
Stealer family/build, HWID, victim IP, OS, target URL and related observations where supplied by the provider.

### Attackers / Attribution
Provider-supplied threat-actor and campaign information. The application does not fabricate attribution.

### Leak Sources
Provider-supplied source, collection/dump and publication metadata.

### References
Provider/source references, including dark-web/forum/marketplace/channel references when explicitly supplied.

### Evidence
Controlled access to raw provider payloads and processing metadata.

### Reports
Executive and technical PDF reports generated from authorized normalized data.

## Repository Authority

Development follows [MasterInstruction.md](MasterInstruction.md).

GitHub `main` is the only source of truth.

## Permanent Development Workflow

```
CURRENT main
  ↓
DEEP INSPECT
  ↓
PRIORITY ANALYSIS
  ↓
ROOT CAUSE
  ↓
SURGICAL CHANGE
  ↓
VALIDATE
  ↓
RE-INSPECT
  ↓
COMMIT TO main
  ↓
RECORD PHASE / VALIDATION / NEXT GATE
  ↓
REPEAT
```

## Migration Status

### Completed
- Repository bootstrap
- Permanent development instruction
- Initial desktop prototype baseline
- Local `.env` loading and secret exclusion

### Current
**Phase 1 — Web Architecture Baseline**

The target architecture has been migrated from a native PyQt6 desktop application to a web application. The existing PyQt6 implementation is historical migration context and is not the target architecture.

### Next
**Phase 2 — Group-IB API Contract Verification**

Before implementing provider integration, verify:

1. authentication mechanism
2. compromised-account endpoint(s)
3. infostealer endpoint(s)
4. attacker/attribution fields
5. leak/source/collection fields
6. dark-web/reference fields
7. timeline/event fields
8. pagination/incremental retrieval
9. status/error behavior
10. actual response schemas

No provider field or endpoint is considered authoritative until verified.

## Development

Target local stack:

```bash
docker compose up --build
```

Backend and frontend commands will be finalized with the Phase 1 implementation scaffold.

## Security Rules

- Never commit Group-IB credentials.
- Never send Group-IB credentials to the browser.
- Never log authorization headers or full secrets.
- Use parameterized database operations.
- Enforce RBAC.
- Redact sensitive intelligence according to policy.
- Preserve evidence provenance and auditability.
- Do not infer or invent threat-actor, leak-source or dark-web attribution.
