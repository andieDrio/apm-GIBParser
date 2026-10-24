# Group-IB Threat Intelligence Monitoring Web Dashboard

A local, single-operator Windows web dashboard being built by extending the existing Group-IB monitoring and PDF reporting project.

## Current status
- Live bounded API contract probe: HTTP 200 for `GET /api/v2/compromised/account_group/updated`, limit 1.
- W1 documentation scope alignment: complete.
- W2 local dashboard shell: implemented; CI validation pending.
- W3 provider-backed account read model: next.
- The current shell deliberately shows no account findings. Filters, classification, assessment and exports are not enabled until actual provider-backed read-model integration is complete.

## Start the local dashboard shell

After pulling the latest `main` and activating your virtual environment:

```powershell
python web_dashboard.py
```

Open http://127.0.0.1:8765 in your browser. The server binds to loopback only. Press Ctrl+C in PowerShell to stop it.

The shell's `/api/health` endpoint reports only whether local credentials are configured; it does not call Group-IB or return credentials.

## Existing daily report

The existing CLI and PDF workflow remains available:

```powershell
python daily_report.py
```

## Credentials
Use the repository's local `.env` file and existing `GROUP_IB_USERNAME` plus `GROUP_IB_API_TOKEN` configuration (legacy `GROUP_IB_API_KEY` fallback is supported by current config). Never paste secrets into source files, browser code, GitHub, screenshots, or chat. `.env` is Git-ignored.

## Dashboard target capabilities
- Filters for last 7 days, last 30 days, and custom dates.
- Separate/group/filter by victim domain.
- Newest-first order based on clearly identified Group-IB source timestamp.
- Preserve Group-IB source categories (Unique / Combolist) independently from NEW / RECYCLED / OLD / UNVERIFIED temporal classification.
- Display provider timeline fields and missing-data warnings honestly.
- Initial deterministic assessment grounded in returned data, baseline availability, and collection completeness.
- Export the selected view to PDF and CSV with filter/provenance metadata.
- Mask sensitive account identifiers by default; exclude passwords and API secrets from dashboard/export output by default.

## Accuracy and limitations
The existing repository contains a Group-IB client, normalizer, local history, classifier, assessment and PDF report pipeline. The bounded updated-feed endpoint has passed a live HTTP 200 contract probe. Full pagination, the date-bounded collection endpoint, and Unique/Combolist filtering are not yet verified by that probe. Never report successful full collection unless all required pages have been retrieved. Missing fields remain missing; partial pagination must be clearly marked.

## Development authority
- Repository: `andieDrio/apm-GIBParser`
- Branch: `main`
- `MasterInstruction.md` is the governing development contract.
- Read `README.md`, `Architecture.md`, and `MasterInstruction.md` before each implementation cycle.
- Preserve the existing daily CLI and report pipeline with regression tests.
