# Group-IB Threat Intelligence Monitoring Web Dashboard

A local, single-operator Windows web dashboard built by extending the existing Group-IB monitoring and PDF reporting project.

## Intended Workflow
```
Group-IB TI&A API
  → validated acquisition
  → canonical normalization
  → durable local history
  → temporal classification
  → domain/date/source filtering
  → initial evidence-based assessment
  → PDF / CSV export
```

The Group-IB API is the authoritative source. The dashboard is read-only. It does not modify provider records or attempt account logins. No mock intelligence is presented as real.

## Windows Setup
Python runtime and dashboard launch commands will be documented after the local web-server gate is implemented. Existing CLI/report workflow remains supported during migration:

```powershell
python daily_report.py
```

## Credentials
Use the repository's local `.env` file and existing `GROUP_IB_USERNAME` plus `GROUP_IB_API_TOKEN` configuration (legacy `GROUP_IB_API_KEY` fallback is supported by current config). Never paste secrets into source files, browser code, GitHub, screenshots, or chat. `.env` is Git-ignored.

## Dashboard Requirements
- Filters for last 7 days, last 30 days, and custom dates.
- Separate/group/filter by victim domain.
- Newest-first order based on clearly identified Group-IB source timestamp.
- Preserve Group-IB source categories (Unique / Combolist) independently from NEW / RECYCLED / OLD / UNVERIFIED temporal classification.
- Display provider timeline fields and missing-data warnings honestly.
- Initial deterministic assessment grounded in returned data, baseline availability, and collection completeness.
- Export the selected view to PDF and CSV with filter/provenance metadata.
- Mask sensitive account identifiers by default; exclude passwords and API secrets from dashboard/export output by default.

## Accuracy and Limitations
The existing repository contains a Group-IB client, normalizer, local history, classifier, assessment and PDF report pipeline. A live API result must still be tested on the Windows machine with the operator's local credentials. Never report successful live authentication unless a real response was observed. Missing fields remain missing; partial pagination must be clearly marked.

## Development Authority
- Repository: `andieDrio/apm-GIBParser`
- Branch: `main`
- `MasterInstruction.md` is the governing development contract.
- Read `README.md`, `Architecture.md`, and `MasterInstruction.md` before each implementation cycle.
- Preserve the existing daily CLI and report pipeline with regression tests.

## Current Gate
W1 — architecture and permanent instructions aligned to the approved Windows web dashboard scope.
