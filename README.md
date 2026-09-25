# Group-IB Daily Threat Intelligence Monitor

A focused local utility for producing a **daily Group-IB threat intelligence quick view and PDF report**.

This project is intentionally small. It is not ThreatForge and is not a general-purpose CTI investigation platform.

## Daily Workflow

The target operator workflow is one command:

```bash
python daily_report.py
```

The command will eventually perform:

```
Group-IB
   ↓
Daily Retrieval
   ↓
Normalize
   ↓
Compare Local History
   ↓
NEW / OLD Classification
   ↓
Quick View + Professional Bar Charts
   ↓
PDF
```

Output:

```
reports/GIB_DailyReport_YYYY-MM-DD_HHMM.pdf
```

## Monitoring Window

Each generated report represents the **previous 24 hours ending at the exact time the script runs**, in Philippines Time (Asia/Manila).

Example:

```
Script run:    Sep 25, 2026 11:13 AM PHT
Window start:  Sep 24, 2026 11:13 AM PHT
Window end:    Sep 25, 2026 11:13 AM PHT
```

The daily report now retrieves an exact rolling 24-hour provider slice using `GET /compromised/account_group?df=<UTC-start>&dt=<UTC-end>&limit=500`, then paginates the returned `resultId` slice. This makes the provider data window itself match the report window. The records are sorted newest-first using `dateLastSeen` with `dateFirstSeen` fallback. The report exposes NEW records with First Seen and Last Seen in PHT.

## What the Daily Report Shows

### Quick View
- report date
- total processed records
- NEW compromises
- OLD / HISTORICAL records
- verified infostealer counts

### NEW Compromises
A separate section for accounts that are newly observed according to the project's durable local-history rules.

### OLD / HISTORICAL
A separate section for previously known or historically dated compromises.

### Timeline
Where available from Group-IB:
- First Seen
- Last Seen
- First Compromised
- Last Compromised

### Professional Bar Charts
The Quick View uses boxed, color-coded bar-chart panels generated only from actual provider data:
- infostealer families and source/collection in one combined panel;
- target domains in a separate panel.

The previous NEW-vs-OLD chart is intentionally omitted from the visual layout. Unavailable fields are omitted rather than fabricated.

## Data Handling

The project keeps a local history so an old compromise returned by Group-IB today does not automatically become a new daily alert.

Sensitive data is minimized:
- credentials stay in `.env`;
- tokens are never printed;
- account identifiers are shown in full for operational report correlation;
- plaintext passwords/session cookies are not included in the daily report by default.

## Current Provider Boundary

The Group-IB runtime contract has now been verified with a successful HTTP 200 response from the configured account. The production boundary uses the verified Personal Token authentication model and the verified `compromised/account_group/updated` endpoint.

The repository contains:

```
tools/groupib_contract_probe.py
tools/groupib_latest_data_probe.py
groupib/client.py
groupib/normalizer.py
tests/test_groupib_client.py
tests/test_groupib_normalizer.py
tests/test_daily_report.py
```

Run the latest-data diagnostic directly with:

```bash
python tools/groupib_latest_data_probe.py
```

It reports provider record count, final sequence cursor, latest provider timestamp and the latest record metadata without printing account/password/cookie values.

The probe reports field names/types without printing response values. The production client validates the provider envelope before normalization, and the canonical model excludes password/session-secret fields.

## Repository Layout

```
apm-GIBParser/
├── daily_report.py              # final one-command entry point
├── groupib/
│   ├── client.py                # verified provider client
│   ├── normalizer.py            # canonical daily records
│   └── classifier.py            # NEW / OLD logic
├── storage/
│   └── history.py               # durable local history
├── reporting/
│   ├── pdf.py                   # ReportLab PDF
│   └── charts.py                # report chart generation
├── reports/                     # generated PDFs, ignored by Git
├── data/                        # local history, ignored by Git
├── tools/
│   ├── groupib_contract_probe.py
│   └── groupib_latest_data_probe.py
├── .env                         # local secrets, ignored by Git
├── requirements.txt
├── Architecture.md
└── MasterInstruction.md
```

## Development Authority

`MasterInstruction.md` is the governing development specification.

GitHub `main` is the only source of truth.

Development follows the permanent loop:

```
CURRENT main
  ↓
DEEP INSPECT
  ↓
PRIORITY
  ↓
SURGICAL CHANGE
  ↓
VALIDATE
  ↓
RE-INSPECT
  ↓
COMMIT main
  ↓
REPEAT
```

## Current Phase

**PHASE 6 — One-Command PDF Reporting — IMPLEMENTED; LATEST-PROVIDER RETRIEVAL GATE IN PROGRESS**

Phases 1–5 are implemented and the daily runtime now generates the PDF. The current reporting gate is focused on professional boxed charts, full account correlation, and Philippines Time presentation for provider timestamps.

The PDF pipeline remains implemented, but the active gate is now provider-data validation. Latest-data retrieval uses the verified `/sequence_list` → `/compromised/account_group/updated?seqUpdate=...` sequence flow without provider-side `df` / `dt`. Records are retained according to the provider's latest sequence stream; `dateLastSeen` is not used as an update-time filter. Once the diagnostic proves current sequence data, the next gate is full end-to-end validation.
