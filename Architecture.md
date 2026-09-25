# Architecture

## Design Goal

Build the smallest reliable system that answers one daily operational question:

> **What new Group-IB compromises should I report today, and which returned records are already old/known?**

The system produces a PDF; it does not require a browser dashboard.

## High-Level Flow

```
┌──────────────────┐
│ Group-IB TI API  │
└────────┬─────────┘
         │
         ▼
┌──────────────────┐
│ Provider Client  │
│ Auth + Retrieval │
└────────┬─────────┘
         │
         ▼
┌──────────────────┐
│ Normalizer       │
│ Canonical Record │
└────────┬─────────┘
         │
         ├───────────────┐
         ▼               ▼
┌──────────────────┐  ┌──────────────────┐
│ Local History    │  │ Daily Classifier │
│ SQLite/local DB  │  │ NEW vs OLD       │
└────────┬─────────┘  └────────┬─────────┘
         └───────────┬─────────┘
                     ▼
             ┌──────────────────┐
             │ Quick View Model │
             │ Metrics + Charts │
             └────────┬─────────┘
                      ▼
             ┌──────────────────┐
             │ ReportLab PDF    │
             └────────┬─────────┘
                      ▼
             reports/GroupIB_...
```

## Monitoring Window

The operational reporting window is a **rolling 24-hour interval ending at the exact script execution time**, expressed in Philippines Time (Asia/Manila).

Example:

```text
Script run:    Sep 25, 2026 11:13 AM PHT
Window start:  Sep 24, 2026 11:13 AM PHT
Window end:    Sep 25, 2026 11:13 AM PHT
```

The provider retrieval starts from the report-window start calendar date via `/sequence_list`, then walks `compromised/account_group/updated?seqUpdate=...` using the sequence cursor only. Returned records are retained from that latest sequence stream. `dateLastSeen` and `dateFirstSeen` are compromise timeline fields, not provider-update timestamps, so they are not used to discard current sequence updates. The rolling 24-hour PHT interval remains report run context until a verified provider-update timestamp is available.

## One-Command Entry Point

```bash
python daily_report.py
```

The entry point owns orchestration only. It should not contain HTTP parsing, classification rules or PDF layout logic.

## Components

### 1. Group-IB Client
Responsibilities:
- load server/local credentials;
- authenticate using the verified Group-IB contract;
- retrieve the latest verified sequence stream;
- retain records according to provider sequence updates rather than filtering on compromise timeline dates;
- handle timeout, HTTP errors and rate limits;
- return provider payloads without leaking secrets.

Provider endpoints and field names are not considered authoritative until verified.

### 2. Normalizer
Convert the verified provider response into a stable internal record.

Minimum directional fields:

```text
provider_record_id
account/email
username
domain
date_first_compromised
date_last_compromised
date_first_seen
date_last_seen
event_count
stealer_family
stealer_build
hwid
victim_ip
operating_system
target_url
source_type
source_name
collection
threat_actor
references
```

All fields are optional except those required by the identity policy.

### 3. Local History
Use a small local durable store. SQLite is the default direction because this tool is single-operator and daily-oriented.

The history store should maintain at least:

```text
compromise_identity
provider_record_id
first_local_seen
last_local_seen
first_provider_seen
last_provider_seen
last_classification
last_observation_fingerprint
updated_at
```

Generated history files belong under `data/` and must remain Git-ignored.

### 4. Identity / Classification

Classification must be based on durable identity, not merely today's retrieval.

Directional identity priority:

1. stable provider record/event identity when available;
2. normalized account + domain + provider compromise identifiers;
3. deterministic fallback fingerprint over normalized fields when provider identity is unavailable.

The fallback must be documented and versioned.

Rules:

```
No local identity match
        ↓
      NEW

Existing identity
        ↓
 OLD / HISTORICAL
```

A returned record may also update local `last_local_seen` without changing its underlying historical identity.

Provider records that are identical observations already processed must be repeat-safe.

### 5. Quick View

The report summary should contain:

```
Report Date
Total Records Processed
NEW Compromises
OLD / HISTORICAL
Infostealer Records
```

Additional metrics are allowed only when supported by actual data.

### 6. Professional Bar Charts

Keep charts intentionally limited and operational.

The current PDF presentation uses:
1. one boxed panel combining infostealer-family and source/collection distributions;
2. one separate boxed target-domain distribution panel;
3. multiple bar colors to improve visual correlation.

The NEW-vs-OLD chart is intentionally omitted from the visual Quick View layout.

No chart should exist solely to make the report look busy.

### 7. PDF Report

ReportLab is the reporting engine.

Recommended structure:

**Page 1 — Daily Quick View**
- title/date
- Asia/Manila (PHT) timezone indicator
- boxed color-coded bar-chart panels
- combined infostealer/source panel
- separate target-domain panel

**Page 2+ — NEW Compromises**
- full account/email identifier for operational correlation
- domain
- First Seen (PHT)
- Last Seen (PHT)
- color-coded stealer/source fields
- threat actor where supplied

**Following section — OLD / HISTORICAL**
- full account/email identifier
- domain
- First Seen (PHT)
- Last Seen (PHT)
- color-coded stealer/source fields

Long tables should paginate cleanly.

## Sensitive Data Boundary

The daily report is not an evidence vault.

Do not include by default:
- plaintext passwords;
- session cookies;
- API tokens;
- authorization headers.

Account/email identifiers are intentionally shown in full for operational report correlation.

Raw provider payload retention is optional and must be explicitly bounded if later introduced.

## Error Behavior

The command must fail safely:

- missing credentials → clear configuration error;
- authentication failure → actionable auth error without secrets;
- rate limit → clear retry guidance;
- invalid provider schema → stop before classification/reporting;
- PDF generation failure → preserve diagnostic context without dumping provider secrets.

Partial output must not be presented as a successful daily report.

## Current Phase

**PHASE 6 — One-Command PDF Reporting & Presentation — LATEST-PROVIDER RETRIEVAL GATE**

Phases 1–5 are implemented. Phase 6 now includes one-command PDF generation, professional boxed color bar charts, full account correlation, and provider timestamp conversion to Asia/Manila (PHT). Runtime/presentation validation is the active gate.

Completed gates:
- Phase 1 — focused daily-monitoring architecture.
- Phase 2 — Group-IB runtime authentication and response-schema verification.

Verified runtime contract evidence:
- Basic authentication with Group-IB web-interface email + Personal API token.
- GET /api/v2/compromised/account_group/updated.
- bounded limit parameter.
- object response with integer count and seqUpdate, plus item records.
- observed timeline, source, malware, service, client, event and attribution fields are normalized only when present.

Phase 3 implementation now provides:
- verified Group-IB HTTP client;
- provider response validation before normalization;
- canonical compromise records;
- deterministic provider-record identity with a documented SHA-256 fallback;
- observation fingerprints that exclude password/session-secret fields;
- unit tests for contract parsing and normalization.

Phase 4 implementation provides:
- SQLite durable compromise history;
- deterministic NEW / OLD/HISTORICAL / RESEEN/RECYCLED / REPEAT outcomes;
- local first/last observation timestamps;
- earliest/latest provider timeline preservation;
- repeat-safe transactional upsert behavior.

Next after validation:
**PHASE 7 — End-to-End Validation**

Latest-data retrieval is implemented using the verified `/sequence_list` → `/compromised/account_group/updated?seqUpdate=...` sequence contract. Provider-side `df` / `dt` and compromise timeline fields are not used to discard current sequence updates. `tools/groupib_latest_data_probe.py` provides an independent provider-current diagnostic before the final Phase 7 end-to-end gate.
