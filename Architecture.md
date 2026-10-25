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

The browser must never call Group-IB directly. The browser must never receive the API token or HTTP Basic Authorization data. The local-only dashboard may display provider-returned compromised account login/password fields to the single operator; CSV/PDF exports must be treated as confidential and include only the active filters.

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

## Provider Contract Boundary
The repository currently documents and implements:
- base URL: `https://tap.group-ib.com/api/v2/`;
- Basic authentication using the Group-IB interface email and Personal API token;
- `compromised/account_group` date-bounded slice with `df`, `dt`, `limit`, and `resultId` continuation;
- `sequence_list` and `compromised/account_group/updated` sequence-based update retrieval;
- strict validation of returned envelope and bounded pagination.

The operator successfully ran the bounded contract probe against `GET /api/v2/compromised/account_group/updated`: HTTP 200, one item at limit 1, JSON object envelope with integer `count` and `seqUpdate`, and an `items` array. Observed item fields include account login, parsed login domain, first/last seen, event-level detected/compromised timestamps, source, malware, evaluation metadata, and a password field. The probe prints only field names/types, not values.

This validates authentication and the observed updated-feed schema for one bounded request only. It does not validate full pagination, the collection slice, or Unique/Combolist filters. Revalidate those before implementing category filters. Do not treat `count` as the total population without confirming endpoint semantics.

## Dashboard Shell (W2)
- Entry point: `python web_dashboard.py`.
- Serves `web/index.html` and `/api/health` using Python's standard library.
- Fixed bind address `127.0.0.1`, port `8765`; no LAN/public bind option.
- Security headers include a restrictive same-origin Content Security Policy, no-sniff, no-referrer, frame denial, and no-store.
- Health response exposes only whether local credentials are configured; it never returns username/token and does not claim to have queried Group-IB.
- Dashboard shell contains no fake account data. Filters/metrics/exports remain visibly unavailable until W3+ is implemented.

## Dashboard Read Model
W3 uses the existing `GroupIBClient.get_compromised_account_slice`, canonical normalizer, and SQLite classifier/history. The browser calls same-origin `GET /api/records?refresh=1&date_from=YYYY-MM-DD&date_to=YYYY-MM-DD`; the backend validates the range (maximum 90 calendar days; provider requests are chunked into at most 30-day slices), retrieves the full bounded provider slice through the existing resultId pagination guard, normalizes it, classifies it once on refresh, and holds the successful snapshot in process memory. A fresh provider collection is required on startup, whenever the date range changes, and every five minutes while the browser tab is visible; changing only domain/source/classification/page-size filters reuses the latest snapshot. Subsequent filter/page requests operate on that snapshot and do not re-run classification or mutate history. A failed refresh does not replace the last successful snapshot.

The JSON read model includes provider refresh time, retrieval/normalization counts, collection-completion state, filter state, page metadata, source category counts, temporal classification counts, and assessment facts. The UI loads automatically on startup, applies filter changes without an Apply button, and displays an in-page alert plus highlighted table rows when NEW-classified records are present. Date changes reuse the loaded snapshot when possible and trigger a provider collection only when the selected range extends beyond the snapshot. It returns masked login identifiers and never serializes plaintext passwords, API tokens or authorization data. NEW requires a valid dateFirstCompromised (falling back only to dateLastCompromised) within the rolling seven-day window; Last Seen, Date Detected, and First Seen cannot independently qualify a record as NEW. If an unknown identity has no valid Compromised Date, classify it UNVERIFIED. Date-range filtering and newest-first sorting use the timeline in this order: dateFirstCompromised, dateLastCompromised, dateDetected, then dateFirstSeen. Last Seen is activity metadata only and must not pull an old compromise into a recent date range. Other filters cover exact normalized domain, exact provider source labels for Unique/Combolist where present, temporal classification, and bounded pagination. Unknown source labels remain Unmapped; category counts are not inferred from unrelated fields.

Collection is limited to the most recent 30 calendar days per request. Custom ranges must fit within that bound. Source-category semantics are still provisional until live values or official documentation confirm exact Unique/Combolist labels. Full retrieval is only claimed when the existing resultId pagination loop completes without provider/schema errors.

### Required filters
- Date preset: last 7 days.
- Date preset: last 30 days (one month).
- Custom date range: inclusive date boundary with validation that start <= end; dashboard selection range is limited to 90 calendar days; each provider slice is limited to 30 days. Malware Family is separately collected from Group-IB over an independent rolling 90-day window, cached for five minutes, and summarized from provider-returned malware family names rather than only records in the selected account date range.
- Victim domain: exact normalized domain filter and domain grouping.
- Source category: Unique / Combolist only where confirmed to be in actual provider contract; unknown values remain Unmapped.
- Temporal label: NEW / RECYCLED / OLD / UNVERIFIED.
- Newest-first order by `dateLastSeen`, falling back to `dateFirstSeen` only when Last Seen is unavailable.
- Provider timestamps remain immutable and distinct from first/last local observation times.
- Partial collection, API errors, normalization warnings and last refresh time are visible.

## Security and Data Handling
- Group-IB credentials remain in local `.env` / backend settings, never in frontend code or browser responses.
- Keep `.env`, DB files, exported CSV/PDF, and runtime data out of Git.
- Bind to loopback by default.
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
- W1 — documentation aligned to approved Windows dashboard scope — **COMPLETE**.
- W2 — local web application shell, loopback-only serving and non-secret health endpoint — **COMPLETE**.
- W3 — provider-backed dashboard read model using client, normalizer and durable history — **IMPLEMENTED; CI validation pending**.
- W4 — validate source-category semantics, complete pagination, domain/date filters and data-quality presentation.
- W5 — verify NEW / RECYCLED / OLD / UNVERIFIED classification with live provider semantics and deterministic tests.
- W6 — evidence-based initial assessment with explicit confidence and limits.
- W7 — filter-faithful PDF and safe CSV exports with provenance.
- W8 — Windows launch/run instructions and end-to-end validation.

Current gate: W3 automated validation, then W4. Live Group-IB validation remains bounded to the existing API probe; dashboard collection has not yet been independently validated live.
