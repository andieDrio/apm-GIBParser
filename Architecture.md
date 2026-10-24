# Architecture — Group-IB Threat Intelligence Monitoring Web Dashboard

## Product Goal
Extend this existing repository into a local, single-operator Windows web dashboard for viewing and exporting Group-IB TI&A compromised-account intelligence. Preserve existing daily PDF functionality, normalized records, deterministic assessment, and SQLite history.

The Group-IB TI&A API remains the authoritative data source. The dashboard is read-only and makes no changes to Group-IB.

## High-Level Data Flow

```
Browser (127.0.0.1)
  ↓ same-origin local HTTP
Python Web Backend
  ↓
Existing Group-IB Client (server-side Personal Token)
  ↓
Validate response / pagination
  ↓
Existing canonical normalizer
  ↓
Existing SQLite history and classification
  ↓
Read model + filters + evidence-based assessment
  ↓
Dashboard / PDF export / CSV export
```

The browser must never call Group-IB directly. The browser must never receive the API token or HTTP Basic Authorization data.

## Windows Runtime
- Target OS: Windows 10/11.
- Local use, single operator.
- Bind to `127.0.0.1` by default.
- Serve static HTML/CSS/JavaScript from the local backend; favor existing dependencies and a small first increment over a large frontend toolchain.
- Retain the existing CLI entry point `python daily_report.py` and current ReportLab output as regression requirements.
- Do not add login/RBAC or multi-user service behavior without explicit scope approval.

## Existing Components to Preserve
- `groupib/client.py`: verified Group-IB Personal Token authentication, bounded collection retrieval, sequence-update path, response validation, pagination protections and safe provider errors.
- `groupib/normalizer.py`: canonical Group-IB record model, normalized timeline fields, provider provenance, deterministic identity/fingerprint logic.
- `storage/history.py` and `storage/classifier.py`: durable local history and deterministic NEW / OLD / RESEEN-RECYCLED / REPEAT decisions.
- `reporting/assessment.py`: deterministic assessment based on actual normalized metrics and evidence.
- `reporting/pdf.py`, `reporting/summary.py`, and `reporting/charts.py`: existing PDF and chart pipeline.
- `tools/groupib_contract_probe.py`: bounded runtime schema probe that reports field names/types without printing response values.
- `daily_report.py`: existing command-line daily report path.

Before changing these modules, fetch latest main and inspect implementation/tests.

## Provider Contract Boundary
The repository currently documents and implements:
- base URL: `https://tap.group-ib.com/api/v2/`;
- Basic authentication using the Group-IB interface email and Personal API token;
- `compromised/account_group` date-bounded slice with `df`, `dt`, `limit`, and `resultId` continuation;
- `sequence_list` and `compromised/account_group/updated` sequence-based update retrieval;
- strict validation of returned envelope and bounded pagination.

This is existing repository evidence, not a claim of a new live API test in this session. Revalidate with `tools/groupib_contract_probe.py` and `tools/groupib_latest_data_probe.py` on the user's configured Windows machine before relying on live dashboard results. Any endpoint/query parameter specific to Unique vs Combolist must be verified from current source docs/runtime schema before implementation.

## Dashboard Read Model
The dashboard exposes only data backed by:
1. actual Group-IB response fields;
2. normalized canonical records;
3. durable local observations/classification;
4. explicit query and collection metadata.

Never synthesize record values when fields are absent. Render missing values as “Not provided” or equivalent.

### Required filters
- Date preset: last 7 days.
- Date preset: last 30 days (one month).
- Custom date range: inclusive date boundary with validation that start <= end.
- Victim domain: exact normalized domain filter and domain grouping.
- Source category: Unique / Combolist only where confirmed to be in actual provider contract.
- Temporal label: NEW / RECYCLED / OLD / UNVERIFIED.
- Newest-first order by a selectable and explicitly labelled source timestamp, defaulting to `dateLastSeen` and falling back to `dateFirstSeen` only when Last Seen is unavailable.
- Provider timestamps remain immutable and distinct from first/last local observation times.
- Partial collection, API errors, normalization warnings and last refresh time are visible.

### Temporal classification
Temporal labels are independent of Group-IB source categories:
- **NEW**: no durable identity match and the source timeline passes the existing documented newness policy.
- **RECYCLED / RESEEN**: an existing identity reappears or has a changed observation according to the existing classifier.
- **OLD / HISTORICAL**: source timeline is outside the newness window or local history confirms prior knowledge.
- **UNVERIFIED**: insufficient/invalid time or identity evidence, conflicting contract data, or incomplete collection prevents a reliable decision.

Use the existing deterministic classifier as the starting point; adjust only with explicit tests. “Unique” does not mean temporally new. “Combolist” does not automatically mean recycled or old. A returned record is not inherently new.

## Initial Assessment
Assessment is deterministic and generated from observed record counts, affected domains, source types, timeline coverage, collection completeness, and prior baseline availability. It must:
- include facts and the precise evidence basis;
- state confidence and data limitations;
- avoid asserting that an account remains accessible or that an organization is safe;
- avoid inventing provider severity;
- identify records needing analyst review without claiming a definitive compromise verdict.

## Export
- PDF: filtered view and assessment, source fields and timestamps, filter criteria, generation time, collection status, source-provenance note.
- CSV: same filtered records and relevant provider fields; quote correctly and neutralize spreadsheet formula injection.
- Exports must match the active filters exactly, including date range, domain, source category, temporal label and sort basis.
- Default mask for account identifiers; no plaintext passwords by default.
- ReportLab remains the PDF renderer.
- API credentials/session data must never appear in any export.

## Security and Data Handling
- Group-IB credentials remain in local `.env` / backend settings, never in frontend code or browser responses.
- Keep `.env`, DB files, exported CSV/PDF, and runtime data out of Git.
- Bind only to loopback by default.
- Validate and bound all date/filter/pagination inputs.
- Parameterize SQLite queries.
- Escape provider-controlled data in HTML.
- Do not accept client-supplied filesystem paths.
- Do not log account passwords, access tokens, authorization headers or raw provider bodies.
- Do not persist raw API responses unless separately designed, bounded and approved.
- Surface incomplete pagination or failed collection instead of presenting partial findings as complete.

## Regression Requirements
The local web dashboard must not break:
- `python daily_report.py`;
- existing deterministic normalization and classification tests;
- existing ReportLab report generation;
- local history compatibility.

## Architecture Gates
- W1: architecture and permanent instructions aligned to dashboard scope.
- W2: local web application shell with loopback-only serving.
- W3: dashboard read model using existing client/normalizer/history.
- W4: date/domain/source filters, newest-first ordering and collection integrity.
- W5: classifications verified with deterministic tests.
- W6: initial evidence-based assessment.
- W7: safe PDF/CSV exports.
- W8: Windows launch and end-to-end regression validation.

Current gate: W1. Live Group-IB access is not validated by documentation review alone.
