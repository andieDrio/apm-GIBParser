# Group-IB Threat Intelligence Desktop Suite

Native macOS CTI desktop application built with PyQt6, Group-IB TI&A API integration and ReportLab PDF reporting.

## Repository Authority
Development follows [MasterInstruction.md](MasterInstruction.md), which defines the permanent development loop and engineering requirements.

## Planned Capabilities
- Group-IB TI&A API key input
- Target/domain filtering
- Compromised account retrieval
- Infostealer telemetry retrieval
- Structured intelligence parsing
- Dashboard metrics
- Credential and infostealer/cookie tables
- Raw JSON/log inspection
- Native macOS PDF export
- Executive metrics and publication-grade reporting
- Local persistence and deterministic deduplication where required

## Layout
```
.
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

## Environment
```bash
python3 -m venv .venv
source .venv/bin/activate
python --version
python -m pip install --upgrade pip
pip install -r requirements.txt
python app.py
```

## Security
Never commit API keys. Sensitive credentials, cookies and infostealer telemetry must not be unnecessarily exposed in logs, UI output or reports. Secret masking and safe persistence are mandatory.

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
NEXT ARCHITECTURE GATE
  ↓
REPEAT
```

## Current Phase
**Phase 0 — Repository Bootstrap**

Completed:
- Master instruction and permanent loop
- Repository documentation baseline

Pending:
- Environment/dependency verification
- Core API client
- GUI
- Persistence
- PDF engine
- End-to-end validation
