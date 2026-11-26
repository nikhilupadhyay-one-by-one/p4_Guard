# P4_Guard hybrid rewrite notes

## Target layout

The runtime application is now one file: `app.py`.

- Monitoring engine, settings, fingerprints, severity rules, burst detection, SQLite access, terminal UI, dashboard server, and CLI live in `app.py`.
- Dashboard HTML, CSS, and JavaScript are embedded in `app.py`; `dashboard.html` is no longer required.
- `tests/test_app.py` is a separate regression-test file, not a runtime module.
- `requirements.txt`, `README.md`, `LICENSE`, CI configuration, and the optional dashboard screenshot are project support files, not application modules.

## Preserved behaviour

- Recursive directory watching and quiet-period debouncing
- Hash, size, permissions, timestamp, and entropy fingerprints
- Default/custom ignore patterns and sensitive-path rules
- Info, notice, warning, and critical severity decisions with reasons
- Detection of mass high-entropy rewrites, excluding common compressed/media formats
- SQLite tracked-file state, append-only event history, and metadata
- Baseline and offline audit commands
- History and statistics commands
- Local dashboard, event polling endpoint, and summary endpoint
- Existing event/table column names so a V2 `guard.db` can be opened without rebuilding its schema

## Reliability and structure changes

- Safe observer initialization: stopping before starting no longer accesses an unset attribute.
- Shutdown is idempotent, including for the database connection.
- Dashboard page is embedded, removing a runtime dependency on `dashboard.html`.
- `watchdog` is imported optionally so `baseline`, `audit`, `history`, and `stats` can still run if the watcher dependency is missing. `watch` gives a direct installation message.
- Dashboard event cursor input is validated rather than allowing a malformed value to raise a request-handler exception.
- Listener failures are reported to stderr and do not terminate the monitoring loop.

No new detection capability or security claim has been introduced. The ransomware logic remains a heuristic, not malware prevention or recovery.

## Verification in this environment

- Python compilation: passed.
- Regression suite: 73 passed, 2 skipped. The skipped cases require the `watchdog` package for real OS filesystem notifications; installing it was blocked because this build environment has no package-index network access.
- CLI help/version: passed.
- Temporary directory baseline followed by a clean audit: passed.
- Dashboard HTML, `/api/summary`, and `/api/events`: passed through a local HTTP smoke test.
- Ruff: not run because Ruff is not installed in this environment.
