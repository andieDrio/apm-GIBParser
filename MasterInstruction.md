# Master Instruction & Permanent Development Loop

## Project
**Group-IB Daily Threat Intelligence Monitor & PDF Reporter**

## Authority
This document is the permanent governing specification for this repository unless explicitly changed by the project owner.

## Objective
Build a small, reliable daily Group-IB monitoring utility whose primary workflow is:

```
Group-IB
   ↓
Daily Retrieval
   ↓
Normalization
   ↓
Local History
   ↓
NEW vs OLD/HISTORICAL Classification
   ↓
Quick View Metrics + Donut Charts
   ↓
Daily PDF Report
```

The project is **not** a general CTI investigation platform, not ThreatForge, and not a multi-user web application. The deliverable is a focused daily monitoring/reporting tool.

## Core User Workflow
The normal operator workflow must eventually be one command:

```bash
python daily_report.py
```

That command should:
1. load Group-IB credentials from local environment configuration;
2. retrieve the configured daily Group-IB intelligence;
3. validate and normalize provider records;
4. compare records against durable local history;
5. classify records as **NEW** or **OLD / HISTORICAL** according to documented rules;
6. calculate daily summary metrics;
7. generate a small number of useful donut charts from actual returned data;
8. generate the dated PDF report automatically under `reports/`;
9. print a concise completion summary without printing secrets or unnecessary sensitive intelligence.

No browser interaction should be required to generate the daily report.

## Scope

### Primary
- Group-IB compromised-account intelligence.
- Daily new-compromise monitoring.
- Separation of previously known/old accounts from daily new compromises.
- First Seen and Last Seen visibility.
- Infostealer fields when explicitly supplied by Group-IB.
- Source/collection fields when explicitly supplied by Group-IB.
- Threat-actor fields when explicitly supplied by Group-IB.
- Target domain/service fields when explicitly supplied by Group-IB.
- Quick View summary.
- Donut charts based only on actual provider data.
- Server/local PDF generation.

### Explicitly out of scope
- ThreatForge functionality.
- General-purpose CTI case management.
- Large React/Next.js dashboard.
- FastAPI service.
- Redis workers.
- PostgreSQL as a mandatory dependency.
- User authentication/RBAC for a single-operator local utility.
- Browser-to-Group-IB integration.
- Fabricated attribution, sources, or dark-web intelligence.
- Complex investigation UI.

The architecture may evolve if the project owner explicitly expands scope.

## Classification Model

### NEW
A normalized compromise that has no matching underlying compromise identity in local history and is within the configured daily/newness policy.

### OLD / HISTORICAL
A compromise already known to local history, or a compromise whose provider timeline clearly predates the configured newness policy, and which does not represent a newly discovered underlying compromise.

A record being returned by Group-IB today does **not** by itself make it NEW.

### RESEEN / RECYCLED
This is an internal processing concept when a known compromise is returned again. For the daily report, it should be grouped with the historical/known population unless the project owner explicitly requests a separate section.

### REPEAT
The same provider observation/event already processed during the current or a prior retrieval. It must not create duplicate local history.

The classification decision must be deterministic and explainable from stored identity/timeline fields.

## Timeline Requirements
Where Group-IB provides them, preserve:
- dateFirstCompromised
- dateLastCompromised
- dateFirstSeen
- dateLastSeen

Also maintain local:
- first locally observed
- last locally observed

The report must clearly distinguish provider timeline fields from local observation timestamps.

## Data Integrity
The local history store is the durable basis for daily NEW-vs-OLD classification.

Identity must not be based only on a timestamp. The implementation must define a deterministic normalized compromise identity using available provider/account/domain/event identifiers and document the fallback behavior when fields are absent.

Repeated provider records must update history rather than blindly create new logical compromises.

## Provider Contract
Group-IB authentication, endpoints, parameters, pagination/incremental retrieval and response fields must be verified before production client implementation.

The existing `tools/groupib_contract_probe.py` is a bounded schema probe. It must not print or persist credentials or response values.

Do not claim a provider field exists unless it is supported by verified documentation or observed runtime schema.

## Security
- Never commit Group-IB credentials.
- Never print API tokens or authorization headers.
- Never write tokens into reports.
- Mask account/email identifiers in reports where practical.
- Do not include plaintext passwords or session cookies in the daily PDF unless explicitly required by a future project-owner change.
- Do not fabricate unavailable source, actor, malware, or dark-web data.
- Keep `.env` ignored by Git.

## Reporting Requirements
The daily PDF should be concise and operational.

### Quick View
- report date
- total records processed
- NEW compromises
- OLD/HISTORICAL records
- infostealer record count when available
- other verified high-value daily metrics

### Charts
Use a restrained set of donut charts, for example:
- NEW vs OLD/HISTORICAL
- infostealer family distribution
- source/collection distribution when the provider supplies it
- target-domain distribution when useful

Do not create charts for unavailable or fabricated fields.

### NEW Compromises
Include a table with useful fields such as:
- masked account/email
- domain
- first seen
- last seen
- stealer
- source
- threat actor

Only include fields actually available.

### OLD / HISTORICAL
Keep this separate from NEW and include:
- masked account/email
- domain
- first seen
- last seen
- stealer
- source

## Reporting File Convention
Reports should be generated automatically as:

```
reports/GroupIB_Daily_Report_YYYY-MM-DD.pdf
```

## Permanent Development Loop
Every cycle MUST follow:
1. Fetch CURRENT latest `main`.
2. Deep-inspect the actual repository.
3. Identify the highest-priority unfinished work.
4. State internally what needs to change.
5. Implement the smallest production-grade surgical change.
6. Validate with executable checks.
7. Re-inspect affected files/contracts.
8. Commit validated work to `main`.
9. Record phase, validation, limitations and next gate.
10. Repeat from the new current `main`.

### Non-negotiable rules
- GitHub `main` is the only source of truth.
- Never rely on stale snapshots, old SHAs, screenshots or previous diagnoses when current code can be inspected.
- Do not rewrite whole files unless genuinely necessary.
- No mock/fake intelligence presented as real.
- No unrelated dependencies or cleanup.
- Resolve root causes rather than symptoms.
- Runtime validation is required where applicable.
- Never request or expose the user's Group-IB secret.

## Phase Gates

### PHASE 1 — Focused Daily-Monitoring Architecture
Define and validate the reduced scope, one-command workflow, local history model and PDF/report structure.

### PHASE 2 — Group-IB Runtime Contract
Complete authentication and response-schema verification using the bounded probe.

**Status: COMPLETE.** Runtime verification succeeded with HTTP 200 using the configured Group-IB Personal Token. The observed response contract includes integer `count` and `seqUpdate`, an `items` array, and the documented/observed compromise, event, malware, source, service and timeline structures.

### PHASE 3 — Daily Retrieval & Normalization
Implement the verified Group-IB client and canonical daily record model.

**Status: COMPLETE.** The verified client uses Basic authentication and the verified `compromised/account_group/updated` endpoint. Provider responses are validated before normalization. Canonical records use provider record identity when available and a deterministic SHA-256 fallback otherwise. Sensitive password/session fields are excluded from the canonical model.

Pagination/incremental retrieval parameters are deliberately deferred until independently verified.

### PHASE 4 — Local History & NEW/OLD Classification
Implement deterministic identity, first/last local observation and repeat-safe classification.

### PHASE 5 — Quick View & Donut Charts
Build the report summary and data-driven charts.

### PHASE 6 — One-Command PDF Reporting
Connect retrieval, classification, summary and ReportLab generation behind `python daily_report.py`.

### PHASE 7 — End-to-End Validation
Validate repeated runs, old-record handling, new-record detection, report generation, redaction and failure behavior.

## Completion Standard
A phase is complete only when implementation and validation evidence exist. After each gate document:
- completed changes,
- validation evidence,
- current phase,
- known limitations,
- next highest-priority gate.
