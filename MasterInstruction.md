# Master Instruction & Permanent Development Loop

## Project
**Group-IB Threat Intelligence Desktop Suite (macOS Native GUI)**

## Authority
This document is the permanent governing specification for this repository unless explicitly changed by the project owner.

## Objective
Build a local standalone macOS CTI desktop application using Python 3.10+, PyQt6 Dark Mode, httpx for Group-IB TI&A API communication, local persistence where required, and ReportLab for executive-ready PDF reporting.

The application accepts a Group-IB TI&A API key, queries supported compromised-account and infostealer intelligence, presents structured telemetry in a native GUI, and exports publication-grade PDF threat reports.

## Required Architecture
```
gib-intel-mac/
├── MasterInstruction.md
├── README.md
├── Architecture.md
├── requirements.txt
├── app.py
├── gib_client.py
├── pdf_generator.py
├── config.py
├── intel_local.db
└── exports/
```

### Module boundaries
- `app.py`: PyQt6 presentation layer, widgets, signals/slots, user interaction, metrics, tables and logs.
- `gib_client.py`: Group-IB API communication, authentication, requests, parsing, timeout and rate-limit handling.
- `pdf_generator.py`: ReportLab report generation, formatting, tables, metrics and export.
- `config.py`: local application settings and secure API-key handling.
- SQLite persistence must remain separated from UI concerns.

## Security Requirements
1. Never hard-code or commit a Group-IB API key.
2. Never expose the full API key in logs, raw JSON, exceptions or reports.
3. Mask secrets in the GUI where appropriate.
4. Validate user-controlled filters before requests.
5. Use safe SQL parameter handling.
6. Minimize persistence of sensitive intelligence.
7. Treat credentials, session cookies and infostealer telemetry as sensitive.
8. Do not claim API capabilities without verification against the actual API contract/runtime behavior.

## Data Integrity
Use deterministic normalization and deduplication for persisted intelligence. The initial requested identity model uses SHA-256 over normalized identifying fields such as HWID + Email + Timestamp. The canonical representation must be documented before persistence is considered production-ready.

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
- Never rely on stale assumptions, old snapshots or previous diagnoses when current code can be inspected.
- Do not rewrite whole files unless genuinely necessary.
- Preserve working behavior and existing UI design unless explicitly changed.
- No mock/fake telemetry presented as real capability.
- No unrelated cleanup or dependencies.
- Resolve root causes rather than symptoms.
- Editing files is not completion; runtime validation is required where applicable.

## Priority Order
1. Backend/application architecture
2. API connectivity and telemetry/data flow
3. API/service/model contracts
4. Authentication and secret handling
5. Data integrity, validation, persistence and error handling
6. Performance, reliability and security
7. GUI/UI/UX
8. Documentation and cleanup

## Phase Gates

### STEP 1 — Environment & Dependencies
Verify macOS Python 3.10+, virtualenv, PyQt6, reportlab and httpx. Maintain reproducible requirements.txt.

### STEP 2 — Modular Architecture
Implement strict separation between GUI, API client, configuration/persistence and PDF generation.

### STEP 3 — PyQt6 UI Event Validation
Run `python app.py` and validate launch, dark styling, controls, events, tables, metrics and logs.

### STEP 4 — PDF Export Verification
Use the native macOS save dialog and validate PDF metrics, tables, pagination, formatting and secret redaction.

## Completion Standard
A phase is complete only when implementation and validation evidence exist. After each gate document current phase, validated capabilities, known limitations and next highest-priority gate.

## Change Control
Any conflict between implementation convenience and this specification is resolved in favor of this Master Instruction unless the project owner explicitly changes it.
