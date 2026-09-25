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
reports/GIB_DailyReport_YYYY-MM-DD.pdf
```

## Daily Monitoring Window

Each generated report represents the full calendar day in Philippines Time (Asia/Manila):
- Start Time: **12:00 Midnight**
- End Time: **11:59 PM**

The current provider retrieval uses the verified `compromised/account_group/updated` contract. Provider-side start/end query parameters are not assumed until independently verified.

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
groupib/client.py
groupib/normalizer.py
tests/test_groupib_client.py
tests/test_groupib_normalizer.py
```

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
│   └── groupib_contract_probe.py
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

**PHASE 6 — One-Command PDF Reporting — IMPLEMENTED; PRESENTATION VALIDATION IN PROGRESS**

Phases 1–5 are implemented and the daily runtime now generates the PDF. The current reporting gate is focused on professional boxed charts, full account correlation, and Philippines Time presentation for provider timestamps.

After PDF presentation/runtime validation, the next gate is **PHASE 7 — End-to-End Validation**.

Pagination/incremental retrieval parameters remain intentionally deferred until independently verified.
