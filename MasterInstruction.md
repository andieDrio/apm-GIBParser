# Master Instruction & Permanent Development Loop

## Project
**Group-IB Threat Intelligence Monitoring Web Dashboard & Report Export**

## Authority
This document is the permanent governing specification for this repository unless explicitly changed by the project owner.

## Objective
Extend the existing Group-IB monitoring and reporting project into a local, single-operator Windows web dashboard while preserving its verified provider client, canonical normalization, durable SQLite history, deterministic classification, evidence-based assessment and ReportLab PDF generation.

The authoritative data source is the configured official Group-IB TI&A API. Do not invent intelligence, provider fields, totals, timestamps, or classifications.

## Core Workflow

```
Windows Browser (localhost)
        ↓
Local Python Web Backend
        ↓
Group-IB TI&A API (server-side credentials)
        ↓
Validate → Normalize → Durable History
        ↓
Unique / Combolist source categories
        ↓
NEW / RECYCLED / OLD / UNVERIFIED timeline classification
        ↓
Domain views → Initial evidence-based assessment
        ↓
PDF / CSV export from retrieved Group-IB records
```

The app is a read-only monitoring and reporting interface. It must not alter Group-IB data, attempt to log in to compromised accounts, or transmit account data to third-party services.

## Required Dashboard Capabilities
- Show compromised-account records retrieved from Group-IB.
- Separate NEW from RECYCLED / OLD based on source evidence and durable local history. Keep ambiguous records UNVERIFIED instead of guessing.
- Preserve Group-IB source category (including Unique and Combolist when exposed by the verified API contract) independently from temporal classification.
- Filter and group records by victim domain.
- Date options: last 1 week, last 1 month (30 days), and custom start/end dates.
- Sort newest to oldest using an explicitly selected and displayed provider timestamp; never overwrite source timestamps.
- Show First Seen, Last Seen, compromised/detected dates where the provider actually supplies them, source type, source, malware/infostealer, threat actor and event counts when available.
- Provide initial deterministic, evidence-linked assessment with confidence and data-coverage caveats.
- Export filtered records to PDF and CSV, preserving source provenance and collection time.
- Clearly display collection status, actual records retrieved, pagination completion, source timestamp basis, last refresh and data-quality warnings.
- Mask sensitive account/credential fields by default. Never display passwords by default, and never export plaintext passwords unless a separate explicit, secure operator workflow is later approved. API keys, authorization headers and session cookies must never appear in frontend responses, logs, exports or source control.
- Support Windows 10/11 local execution and browser access via localhost. Bind to loopback by default, not a public network interface.

## Stack Direction
- Backend: existing Python codebase; keep the first local HTTP server dependency-free where practical.
- Frontend: lightweight static HTML/CSS/JavaScript dashboard served by the backend; do not add a large frontend framework without a demonstrated need.
- Persistence: preserve existing SQLite durable history.
- PDF: preserve existing ReportLab report pipeline and add dashboard-filtered export in a controlled way.
- Credentials: existing local .env and server-side configuration only.
- Keep current CLI daily report working during web-dashboard implementation.

## Official Group-IB API Contract
- Use the existing Group-IB client and verified contract as the starting point; do not replace it with a guessed endpoint.
- The repository records a verified Personal Token authentication model and bounded Group-IB collection/sequence-update endpoints. Reinspect current source and tests before any API contract change.
- Live bounded contract probe returned HTTP 200 from `GET /api/v2/compromised/account_group/updated`, with one item at limit 1 and a JSON object containing integer `count`, integer `seqUpdate`, and an `items` array. Observed schema includes login, parsedLogin.domain, first/last seen timestamps, event detected/compromised dates, source, malware, evaluation and a password field.
- This validates the observed updated-feed response only. Collection-slice pagination and Unique/Combolist query semantics remain unverified.
- Respect existing pagination guards, timeout/error handling and rate limits.
- Never print or persist real credentials or raw response values in diagnostic output; report field names/types only.

## Classification and Accuracy
- NEW means a record has no matching durable identity and passes the documented newness/timeline rules. The current classifier's configured policy remains authoritative until changed with tests.
- RECYCLED / RESEEN means a previously known identity has resurfaced or changed observation fingerprint according to the existing classifier.
- OLD / HISTORICAL means provider timeline is outside the configured newness window or local history demonstrates a known record, according to existing classification semantics.
- UNVERIFIED means required provider timestamps or identity fields are missing/invalid, the source contract is ambiguous, or collection is partial in a way that could change the conclusion.
- Source categories Unique / Combolist are independent from temporal labels.
- A record returned today is not automatically new.
- A clean/empty query is not evidence the monitored environment is safe.
- Keep UTC-aware provider timestamps in canonical storage; render local timezone labels clearly (Asia/Manila).
- Domain grouping uses normalized domain fields but preserves original provider values for provenance.
- New source fields or filters must be grounded in actual provider response schema or verified official documentation.

## Data Integrity and History
- Reuse the existing `groupib/`, `storage/`, and `reporting/` logic where possible.
- Preserve deterministic identities and observation fingerprints; never fingerprint or log plaintext passwords.
- History mutation must be transactional and repeat-safe.
- Do not classify/export a supposedly complete result if provider pagination failed. Indicate partial/failed retrieval explicitly.
- Never replace provider First Seen / Last Seen with local observation timestamps; display local observation times separately when needed.
- Maintain consistent source provenance from collection to table and exported report.

## Security
- Never commit Group-IB credentials.
- Never print API tokens or authorization headers.
- Never write API tokens, session cookies or auth headers into reports.
- Keep `.env`, local databases, exports, reports and generated runtime data Git-ignored as appropriate.
- Validate date ranges and domain filters on the backend; parameterize database queries.
- Prevent arbitrary filesystem paths from client input.
- Render provider-supplied strings as escaped text; never inject them as HTML.
- Use safe generic errors in HTTP responses while preserving non-sensitive operator diagnostics.
- Bind to 127.0.0.1 by default. Do not expose the app on a LAN/public interface without an explicit future security design.
- Minimize credential exposure. Mask account identifiers by default where practical. Do not include plaintext passwords in dashboard output or exports by default.

## Export Requirements
- PDF and CSV output must reflect the exact currently selected date, source category, domain and temporal classifications.
- Export metadata: generated-at timestamp, query/filter definitions, Group-IB API source, collection-completion state, number of returned/exported records, and source timestamp used for sorting.
- PDF reports must state that assessment is an initial deterministic analyst aid, not proof of active access or a definitive severity verdict.
- Do not label a report complete if pagination or normalization is incomplete.
- Escape CSV values that could be interpreted as spreadsheet formulas (e.g. values beginning with =, +, -, or @).

## Permanent Development Loop
Every cycle MUST follow:
1. Fetch the current remote `main`.
2. Read `README.md`, `Architecture.md`, and `MasterInstruction.md`.
3. Deep-inspect the actual affected implementation and tests.
4. Identify the highest-priority unfinished gate.
5. Implement the smallest coherent production-grade change.
6. Run executable tests and applicable lint/build checks.
7. Re-inspect changed code and contracts.
8. Commit directly to `main` only after validation, preserving fast-forward history.
9. Fetch remote `main` again and verify the resulting commit SHA.
10. Report exact changed files, validation evidence, verified SHA, limitations, and next gate.

## Change Discipline
- GitHub `main` is the only source of truth.
- No feature branches, pull requests, force pushes or history rewriting unless explicitly requested by the project owner.
- Never trust stale SHAs or old snapshots when current main can be fetched.
- Do not rewrite existing working modules unnecessarily.
- No fake/mock intelligence presented as real.
- Do not expand dependencies without justification.
- Fix test/build/runtime failures before moving to the next gate.
- Keep the existing CLI and PDF behavior working as regression requirements.

## Architecture Gates
- W1 — scope and architecture documentation aligned to approved Windows dashboard — **COMPLETE**.
- W2 — local web server shell, safe static dashboard delivery, loopback-only binding and non-secret health endpoint — **IMPLEMENTED; CI validation pending**.
- W3 — dashboard read model backed by existing normalization/history and verified Group-IB acquisition.
- W4 — date/domain/source/category filters, newest-first sorting, pagination completeness and data-quality presentation.
- W5 — NEW / RECYCLED / OLD / UNVERIFIED temporal classification validated against deterministic tests and actual source semantics.
- W6 — evidence-based initial assessment with explicit confidence and limits.
- W7 — filter-faithful PDF and safe CSV exports with provenance.
- W8 — Windows launch/run instructions, regression checks and end-to-end validation.

Current next gate: **W2 automated validation, then W3 provider-backed read model**. Do not claim web dashboard or complete live data collection is done until implemented and verified.

## Reporting Standard
Every development response states:
- gate addressed;
- actual changes;
- tests executed and results;
- commit SHA and current remote main SHA if a push happened;
- live Group-IB validation status;
- next gate.
