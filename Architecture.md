# Architecture

## System Overview
```
┌────────────────────────────────────────────────────────────┐
│                     PyQt6 Desktop UI                      │
│                         app.py                             │
│ API Key │ Domain Filter │ Metrics │ Tables │ Raw Logs     │
└───────────────────────────┬────────────────────────────────┘
                            │
                            ▼
┌────────────────────────────────────────────────────────────┐
│                  Group-IB API Client                       │
│                      gib_client.py                         │
│ Auth │ Requests │ Timeouts │ 429 │ Response Parsing       │
└───────────────────────────┬────────────────────────────────┘
                            │
                            ▼
                     Group-IB TI&A API
                            │
                            ▼
┌────────────────────────────────────────────────────────────┐
│              Normalization / Persistence                   │
│ Canonical Records │ Deduplication │ SQLite │ Read-back    │
└───────────────────────────┬────────────────────────────────┘
                            │
                            ▼
┌────────────────────────────────────────────────────────────┐
│                  Report Generation                         │
│                     pdf_generator.py                        │
│ Metrics │ Tables │ Risk Indicators │ Pagination            │
└────────────────────────────────────────────────────────────┘
```

## Responsibilities

### app.py
Presentation only: PyQt6 widgets, signals/slots, user actions, dashboard metrics, table rendering, status and raw-log presentation.

### gib_client.py
External API boundary: authentication, HTTP requests, endpoint methods, timeouts, HTTP error mapping, rate-limit handling and response normalization.

### config.py
Application configuration boundary: local settings and secure API-key handling.

### Persistence
SQLite/local storage owns normalized intelligence records, deduplication and read-back integrity. UI must not contain persistence logic.

### pdf_generator.py
ReportLab boundary: executive summary, metrics, data tables, risk indicators, pagination and output path handling.

## Data Flow
```
User Input
   ↓
GUI Validation
   ↓
API Client
   ↓
Group-IB TI&A
   ↓
Response Validation
   ↓
Canonical Normalization
   ↓
Deduplication / Persistence
   ↓
Dashboard + Tables
   ↓
PDF Report
```

## Validation Gates

### Gate 1 — Environment
Python 3.10+, virtualenv and required packages.

### Gate 2 — Architecture
Module boundaries and dependency direction are preserved.

### Gate 3 — UI
`python app.py`; verify events, tables, metrics and dark theme.

### Gate 4 — API
Verify authentication, successful retrieval, timeout handling, 429 handling and safe error presentation.

### Gate 5 — Persistence
Verify normalization, deterministic identity, deduplication and read-back integrity.

### Gate 6 — PDF
Verify native save dialog, report structure, table layout, pagination and secret redaction.

### Gate 7 — End-to-End
Fetch → normalize → persist → display → export → reopen/read-back verification.

## Security Boundary
Secrets and sensitive intelligence must never cross into debug output, generated reports or source control unless explicitly required and appropriately redacted.
