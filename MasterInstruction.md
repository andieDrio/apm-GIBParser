# Master Instruction & Permanent Development Loop

## Project
**Group-IB Threat Intelligence Web Application**

## Authority
This document is the permanent governing specification for this repository unless explicitly changed by the project owner.

## Objective
Build a production-grade web-based CTI investigation and reporting platform for Group-IB TI&A intelligence.

The platform must securely ingest Group-IB intelligence, preserve raw evidence, normalize findings into a canonical model, maintain durable observation history, distinguish **NEW**, **OLD/HISTORICAL**, **RESEEN/RECYCLED**, and **REPEAT** findings, and expose investigation-ready views for compromised accounts, infostealers, attackers, leak provenance, dark-web references and related evidence.

The application is a **web application**, not a native macOS desktop application.

## Target Architecture
- Frontend: React / Next.js with TypeScript and Tailwind CSS.
- Backend API: FastAPI with Python.
- Background ingestion: asynchronous worker architecture using Redis as the queue/cache boundary.
- Database: PostgreSQL as the system of record.
- Raw evidence: controlled evidence storage; PostgreSQL JSONB may be used for bounded raw payloads, with an object-storage boundary available for larger evidence.
- Reporting: server-side PDF generation.
- Authentication/authorization: secure web authentication with RBAC.
- Deployment: Docker Compose for local development and a production containerized deployment path.

## Core Intelligence Capabilities
1. Secure Group-IB API credential configuration on the server side.
2. Group-IB API contract verification before production integration.
3. Compromised account intelligence.
4. Infostealer intelligence and stolen session/cookie indicators where licensed API responses expose them.
5. Attacker/threat-actor attribution when explicitly provided by Group-IB.
6. Leak provenance and source/collection metadata when explicitly provided.
7. Dark-web/forum/marketplace/channel references when explicitly provided.
8. Target URL/domain/service context.
9. Timeline fields including first/last compromised and first/last observed where available.
10. Event counts and observation history.
11. Durable canonical normalization and deterministic identity.
12. Newness/lifecycle classification:
   - **NEW** — newly discovered by this platform according to the configured detection/observation policy.
   - **OLD / HISTORICAL** — known compromise whose underlying compromise predates the configured newness window.
   - **RESEEN / RECYCLED** — an existing compromise that is observed again or returned again by the provider without representing a new underlying compromise.
   - **REPEAT** — the same provider observation/event has already been processed and should not create another logical finding.
13. Search, filtering, sorting, investigation details and evidence drill-down.
14. Executive and technical reporting.

## Canonical Intelligence Model
Every normalized finding should support, where available:

### Identity
- provider record ID
- account/email
- username
- domain
- canonical fingerprint

### Timeline
- dateFirstCompromised
- dateLastCompromised
- dateFirstSeen
- dateLastSeen
- local first seen
- local last seen
- event count

### Exposure
- password availability/type
- target URL/service
- cookies/session indicators
- other exposed artifacts

### Infostealer
- stealer family
- malware build/version
- HWID
- victim IP
- operating system
- infection/observation timestamps

### Attribution
- attacker/threat actor name or ID when explicitly supplied
- campaign
- infrastructure
- attribution metadata/confidence when supplied

### Leak Provenance
- source type
- source name
- collection/dump name
- publication date
- first observed date
- source/reference identifiers
- dark-web reference metadata when supplied

### Evidence
- raw provider payload
- endpoint used
- request/query metadata excluding secrets
- ingestion timestamp
- schema/version metadata
- processing/audit metadata

**Do not infer attacker identity, dark-web source, breach origin or attribution from incomplete data. Null is preferable to fabricated intelligence.**

## Security Requirements
1. Never expose or commit Group-IB API credentials.
2. Group-IB credentials remain server-side and are never sent to the browser after configuration.
3. Never log full API keys, authorization headers, passwords, session cookies or equivalent secrets.
4. Encrypt sensitive secrets at rest where persistence is required.
5. Enforce authentication and RBAC on all protected application/API routes.
6. Validate and normalize all user-controlled filters and query parameters.
7. Use parameterized SQL/ORM queries only.
8. Apply output encoding and XSS protections.
9. Protect against CSRF where applicable to the chosen authentication model.
10. Apply secure CORS policy.
11. Apply request size, pagination and rate limits.
12. Separate tenant/user authorization from provider credentials if multi-user access is enabled.
13. Minimize retention of plaintext credentials and session cookies.
14. Redact sensitive values in UI, logs, reports and error messages unless explicitly authorized for investigation.
15. Preserve evidence integrity with immutable/raw evidence boundaries and audit metadata.
16. Do not claim API capabilities without verification against the actual Group-IB contract/runtime behavior.

## Data Integrity Requirements
The database is the system of record for normalized intelligence and observation history.

The identity model must distinguish:
- provider identity,
- underlying compromise identity,
- provider observation/event identity,
- local ingestion occurrence.

A provider record appearing again must not automatically become a new finding.

Canonical normalization and fingerprinting must be deterministic, versioned and documented before production persistence is considered complete.

## Permanent Development Loop
Every cycle MUST follow:

1. Fetch CURRENT latest `main`.
2. Deep-inspect the actual repository.
3. Identify the highest-priority unfinished work.
4. Define the smallest production-grade change.
5. Implement surgical changes.
6. Validate with executable checks.
7. Re-inspect affected files and contracts.
8. Commit validated work to `main`.
9. Record changes, validation evidence, current phase and next gate.
10. Repeat from the new current `main`.

### Non-negotiable rules
- GitHub `main` is the only source of truth and authority.
- Never rely on stale assumptions, old snapshots, previous diagnoses or screenshots when current code can be inspected.
- Do not rewrite whole files unless genuinely necessary.
- Preserve working behavior unless the architecture migration explicitly requires replacement.
- No mock/fake telemetry presented as real capability.
- No unrelated cleanup or dependencies.
- Resolve root causes rather than symptoms.
- Editing files is not completion; runtime validation is required where applicable.
- API contracts must be verified before implementation claims are made.

## Priority Order
1. Backend/application architecture
2. API connectivity and telemetry/data flow
3. API/service/model contracts
4. Authentication and authorization
5. Data integrity, validation, persistence and error handling
6. Performance, reliability and security
7. Frontend/UI/UX
8. Reporting
9. Documentation and cleanup

## Migration Phase Gates

### PHASE 1 — Web Architecture Baseline
Complete when the web architecture, service boundaries, data model direction, security boundaries and development workflow are documented.

### PHASE 2 — Backend/API Contract
Verify Group-IB authentication, endpoints, parameters, pagination/incremental retrieval and response schemas before production integration.

### PHASE 3 — Canonical Intelligence Pipeline
Implement raw evidence capture, schema validation, canonical normalization, deterministic identity and durable observation history.

### PHASE 4 — Lifecycle Classification
Implement and validate NEW / OLD-HISTORICAL / RESEEN-RECYCLED / REPEAT classification against persisted observations.

### PHASE 5 — Persistence Integrity
Implement PostgreSQL repositories, constraints, transactions, idempotent ingestion and read-back verification.

### PHASE 6 — Web Application
Implement authenticated React/Next.js investigation UI, dashboards, search, filters, detail views and evidence drill-down.

### PHASE 7 — Reporting
Implement executive and technical PDF reporting with secret/data redaction controls.

### PHASE 8 — End-to-End Validation
Validate provider retrieval → raw evidence → normalization → persistence → classification → API → UI → reporting.

## Completion Standard
A phase is complete only when implementation and validation evidence exist. After each gate document:
- completed changes,
- validation evidence,
- current phase,
- known limitations,
- next highest-priority gate.

## Change Control
Any conflict between implementation convenience and this specification is resolved in favor of this Master Instruction unless the project owner explicitly changes it.
