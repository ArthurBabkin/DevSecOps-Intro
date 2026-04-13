# Lab 10 — Vulnerability Management with DefectDojo

## Task 1 — Local setup

Cloned Dojo under `labs/lab10/setup/django-DefectDojo` (how to repeat it is in `labs/lab10/setup/README.md`; that folder stays out of git). Then `docker compose pull`, `up -d`, `docker compose ps`, browser on `http://localhost:8080`, login `admin` / password from `docker compose logs initializer | grep "Admin password:"`.

Product type **Engineering**, product **Juice Shop**, engagement **Labs Security Testing** appeared on their own when imports ran with `auto_create_context=true` — I didn’t click them together first in the UI.

## Task 2 — Imports

`DD_API` + `DD_TOKEN` in the shell, then `bash labs/lab10/imports/run-imports.sh`. Each `curl` response is a JSON under `labs/lab10/imports/`.

ZAP: Dojo wants **Traditional XML** for **ZAP Scan**, lab 5 only had **JSON**. First try failed (`import-zap-json-format-rejected.json`). I used `zap_json_to_dojo_xml.py` → `zap-report-noauth.xml`, imported that, and `run-imports.sh` looks for the xml first.

Semgrep / Trivy / Nuclei / Grype: straight from the paths baked into the script.

There may be a dead empty **ZAP Scan** test left from the failed JSON import; counts below are from the import that actually worked (for me that was test id **6**).

## Task 3 — Reporting and metrics

After everything was in Dojo I froze numbers in `metrics-snapshot.md` (severity, open vs closed, verified/mitigated, SLA bit, CWEs, breakdown per test). I refresh that file with `labs/lab10/report/build_artifacts.py` when the DB changes.

`findings.csv` is the full engagement pulled through the API — same kind of dump as the CSV export in the product, I didn’t hand-copy anything.

`dojo-report.html` is the big HTML from **`/engagement/<id>/report`** after a normal login. I pulled it down with `fetch_ui_engagement_report.py` + `DD_PASSWORD` so I don’t have to babysit the browser every time; it’s still the app’s own page, not something I typed up by hand.

`dojo-metrics-rollup.html` is just the small tables from `build_artifacts.py` for my own overview — keep it separate from the Dojo HTML.

### Summary bullets (metrics)

- Open vs closed: in this export everything is still **open** (1444 active); **closed** is **0** in every severity bucket — details in `metrics-snapshot.md`.
- Roughly **1.4k** open rows total. **Trivy** carries most of it, **Grype** is second, the rest (Semgrep / Nuclei / ZAP) are smaller. No dedupe work, so the engagement is noisy.
- Severity: a lot of **Low**, still plenty of **High/Critical** from image CVE noise, **Medium** is more of the “app scanner” layer.
- **143** opens are marked **verified** (largely how Trivy landed); **mitigated** is **0** because I didn’t work tickets, just ran the lab.
- **22** opens had SLA inside **14 days** on the snapshot date. Non-zero CWEs that keep showing up are things like **1333**, **407**, **79**, **22** — if you squint, that’s a bit more narrative than “yet another CVE list”.

## Cleanup

```bash
cd labs/lab10/setup/django-DefectDojo && docker compose down
```

Don’t commit passwords, API tokens, or the `django-DefectDojo/` tree.

## Artifacts (this PR)

| Path | What it is |
|------|------------|
| `labs/lab10/imports/run-imports.sh` | bulk import; ZAP prefers `zap-report-noauth.xml` in this folder |
| `labs/lab10/imports/zap_json_to_dojo_xml.py` | JSON → XML for Dojo’s ZAP importer |
| `labs/lab10/imports/zap-report-noauth.xml` | ZAP input Dojo actually accepted |
| `labs/lab10/imports/import-*.json` | raw import API responses (incl. ZAP json fail + xml ok) |
| `labs/lab10/report/metrics-snapshot.md` | snapshot markdown |
| `labs/lab10/report/findings.csv` | all findings as CSV |
| `labs/lab10/report/dojo-report.html` | engagement report HTML from Dojo UI (saved via `fetch_ui_engagement_report.py`) |
| `labs/lab10/report/dojo-metrics-rollup.html` | extra API rollup tables |
| `labs/lab10/report/build_artifacts.py` | CSV + snapshot + rollup from API |
| `labs/lab10/report/fetch_ui_engagement_report.py` | session login + download `/engagement/<id>/report` HTML |
| `labs/lab10/setup/README.md` | how to clone + run Dojo again |
