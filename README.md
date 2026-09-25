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

## Latest Provider Lookback

The PDF header always represents the exact previous 24-hour execution window. Provider acquisition is intentionally broader so current Group-IB account records are not lost simply because their First Seen/Last Seen timeline is older than 24 hours.

Default:

```bash
GROUP_IB_LATEST_LOOKBACK_DAYS=30
```

The value may be reduced for testing, but must not exceed 30 days. The provider collection slice is paginated with `resultId`.

## Monitoring Window

Each generated report represents the **previous 24 hours ending at the exact time the script runs**, in Philippines Time (Asia/Manila).

Example:

```
Script run:    Sep 25, 2026 11:13 AM PHT
Window start:  Sep 24, 2026 11:13 AM PHT
Window end:    Sep 25, 2026 11:13 AM PHT
```

The daily report keeps a rolling 24-hour **reporting window**, but provider acquisition uses a separate bounded latest-data lookback. By default, the client retrieves the most recent 30 days from `GET /compromised/account?df=<UTC-start>&dt=<UTC-end>&limit=500` and follows `resultId` pagination. This is intentionally broader than the report window so current Group-IB account records whose First Seen/Last Seen dates are older than 24 hours are not incorrectly discarded. Records are sorted newest-first using `dateLastSeen` with `dateFirstSeen` fallback. NEW classification still uses durable local history and the configured newness policy, while Compromised Date, First Seen and Last Seen are displayed in PHT.

### Daily Operational Summary

The report now includes:
- Executive Summary with total records, NEW compromises, seven-day detected count, affected-domain count, seven-day total and daily average.
- Daily Delta against the most recent successfully generated report.
- Newly Affected Domains, based on domains not present in the previous successful run.
- Collection/data-quality and run metadata.
- Durable daily-run summaries stored in the local SQLite history database.

A first run establishes the baseline; delta and newly-affected-domain comparisons become available on the next successful run.

### Validation

Unit tests are executed automatically by GitHub Actions on pushes to `main` and pull requests.

### Automated Daily Threat Assessment

Every generated PDF now includes a deterministic, ready-made assessment derived only from the current normalized Group-IB data and the previous successful daily baseline when available.

The assessment contains:
- **Activity Level** — `NO NEW ACTIVITY`, `OBSERVED ACTIVITY`, or `ELEVATED ACTIVITY` under documented local rules;
- **Assessment Confidence** — `LIMITED`, `MODERATE`, or `HIGH`, based on baseline availability and source-link evidence coverage;
- **Facts** and **Key Observations** tied to report metrics;
- **Assessment** bounded to observed Group-IB intelligence;
- **Recommended Analyst Attention** based on actual findings;
- **Assessment Basis** showing the underlying counts.

The assessment is deterministic and local; it does not use an LLM and does not claim that absence of NEW records means an environment is safe.


## What the Daily Report Shows

### Quick View
- report date
- total processed records
- NEW compromises
- OLD / HISTORICAL records
- verified infostealer counts

### NEW Compromises
A separate section for accounts that are newly observed according to the project's durable local-history rules and whose provider compromise/detection timeline falls within the default 7-day NEW window.

### NEW Compromise Trend
The PDF includes a dedicated seven-day bar chart showing NEW compromised-account counts by provider compromise/detection date.

### NEWLY DETECTED
The report separately displays the number of provider records with a Date Detected timestamp in the last 7 days.

### OLD / HISTORICAL
A separate section for previously known or historically dated compromises.

### Timeline
Where available from Group-IB:
- Compromised Date
- Date Detected
- First Seen
- Last Seen
- Source Link

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
- provider-supplied login/password fields are included in the daily operational report by explicit project-owner request; API tokens and session cookies are never included.

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

The probe reports field names/types without printing response values. The production client validates the provider envelope before normalization, and the canonical model includes the provider password only for the explicitly requested operational report; API tokens/session cookies remain excluded.

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
│   ├── assessment.py            # deterministic daily assessment
│   ├── pdf.py                   # ReportLab PDF
│   ├── summary.py               # Quick View metrics
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

**PHASE 7 — End-to-End Validation & Evidence-Based Assessment — ACTIVE**

Phases 1–5 are implemented and the daily runtime now generates the PDF. The current reporting gate is focused on professional boxed charts, full account correlation, and Philippines Time presentation for provider timestamps.

The PDF pipeline remains implemented, including the deterministic daily assessment. The active gate is now end-to-end validation of assessment output, baseline-aware confidence, Daily Delta behavior and real Group-IB runtime data. Daily report acquisition uses a bounded current-data lookback through `/compromised/account_group` with `df` / `dt` and `resultId` pagination. The default lookback is 30 days, while the PDF header remains the exact rolling 24-hour execution window. Sequence-based `/sequence_list` → `/compromised/account_group/updated?seqUpdate=...` retrieval remains implemented as the verified incremental/latest-update diagnostic path.
