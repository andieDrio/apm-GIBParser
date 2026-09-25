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
- retrieve the required daily collection;
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

### 6. Donut Charts

Keep charts intentionally limited.

Recommended:
1. NEW vs OLD / HISTORICAL.
2. Infostealer family distribution.
3. Source/collection distribution when available.
4. Target-domain distribution when materially useful.

No chart should exist solely to make the report look busy.

### 7. PDF Report

ReportLab is the reporting engine.

Recommended structure:

**Page 1 — Daily Quick View**
- title/date
- summary metrics
- donut charts
- short operational summary

**Page 2+ — NEW Compromises**
- masked account
- domain
- first seen
- last seen
- stealer
- source
- threat actor where supplied

**Following section — OLD / HISTORICAL**
- masked account
- domain
- first seen
- last seen
- stealer
- source

Long tables should paginate cleanly.

## Sensitive Data Boundary

The daily report is not an evidence vault.

Do not include by default:
- plaintext passwords;
- session cookies;
- API tokens;
- authorization headers.

Mask account/email identifiers in the report.

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

**PHASE 3 — Daily Retrieval & Normalization**

Implementation is in place; final phase completion requires the local executable test suite to pass.

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

Next after validation:
**PHASE 4 — Local History & NEW/OLD Classification**

Pagination/incremental retrieval parameters remain intentionally unimplemented until their runtime parameter contract is independently verified.
