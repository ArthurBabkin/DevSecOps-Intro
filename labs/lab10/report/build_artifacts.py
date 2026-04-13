#!/usr/bin/env python3
import csv
import json
import os
import sys
import urllib.error
import urllib.request
from collections import Counter
from datetime import date
from pathlib import Path


def get_json(url, token):
    r = urllib.request.Request(url, headers={"Authorization": f"Token {token}"})
    with urllib.request.urlopen(r, timeout=120) as resp:
        return json.loads(resp.read().decode())


def main() -> int:
    base = os.environ.get("DD_API", "http://localhost:8080/api/v2").rstrip("/")
    token = os.environ.get("DD_TOKEN", "")
    if not token:
        print("need DD_TOKEN", file=sys.stderr)
        return 1
    eid = os.environ.get("DD_ENGAGEMENT_ID", "1")
    out = Path(__file__).resolve().parent

    data = get_json(f"{base}/findings/?engagement={eid}&limit=5000", token)
    rows = data.get("results") or []
    if data.get("next"):
        print("WARN: hit pagination, bump limit", file=sys.stderr)

    cols = [
        "id",
        "title",
        "severity",
        "active",
        "verified",
        "is_mitigated",
        "false_p",
        "cwe",
        "test",
        "found_by",
        "sla_days_remaining",
        "sla_expiration_date",
        "created",
    ]
    csv_path = out / "findings.csv"
    with csv_path.open("w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=cols, extrasaction="ignore")
        w.writeheader()
        for row in rows:
            line = {}
            for k in cols:
                v = row.get(k, "")
                if isinstance(v, (list, dict)):
                    v = json.dumps(v, ensure_ascii=False)
                line[k] = v
            w.writerow(line)

    active = [r for r in rows if r.get("active")]
    sevs = ["Critical", "High", "Medium", "Low", "Info"]
    by_sev_open = Counter((r.get("severity") or "Unknown") for r in active)
    closed = [r for r in rows if not r.get("active")]
    by_sev_closed = Counter((r.get("severity") or "Unknown") for r in closed)
    n_verified = sum(1 for r in active if r.get("verified"))
    n_mitigated = sum(1 for r in rows if r.get("is_mitigated"))

    per_test: Counter[int] = Counter()
    for r in active:
        if r.get("test") is not None:
            per_test[int(r["test"])] += 1

    titles: dict[int, str] = {}
    for tid in list(per_test.keys()):
        try:
            t = get_json(f"{base}/tests/{tid}/", token)
            st = t.get("scan_type")
            if isinstance(st, dict):
                stn = st.get("name", "")
            else:
                stn = str(st or "")
            titles[tid] = t.get("title") or stn or str(tid)
        except (urllib.error.HTTPError, urllib.error.URLError, KeyError, TypeError):
            titles[tid] = str(tid)

    sla_14 = sum(
        1
        for r in active
        if r.get("sla_days_remaining") is not None and int(r["sla_days_remaining"]) <= 14
    )

    cwes: Counter[int] = Counter()
    for r in active:
        c = r.get("cwe")
        if c is not None and int(c) > 0:
            cwes[int(c)] += 1
    top_cwe = cwes.most_common(8)

    snap = out / "metrics-snapshot.md"
    buf = [
        "# Metrics Snapshot — Lab 10",
        "",
        f"- Date captured: {date.today().isoformat()}",
        "- Active findings:",
    ]
    for s in sevs:
        buf.append(f"  - {s}: {by_sev_open.get(s, 0)}")
    if by_sev_open.get("Unknown"):
        buf.append(f"  - Other/Unknown: {by_sev_open['Unknown']}")
    buf.append("- Closed (inactive) findings by severity:")
    if not closed:
        for s in sevs:
            buf.append(f"  - {s}: 0")
    else:
        for s in sevs:
            buf.append(f"  - {s}: {by_sev_closed.get(s, 0)}")
        if by_sev_closed.get("Unknown"):
            buf.append(f"  - Other/Unknown: {by_sev_closed['Unknown']}")
    buf += [
        f"- Verified (among active): {n_verified}",
        f"- Mitigated (all findings in export): {n_mitigated}",
        f"- Active findings with SLA horizon ≤ 14 days: {sla_14}",
        "- Top CWE (active, CWE>0): "
        + (", ".join(f"CWE-{c} ({n})" for c, n in top_cwe) if top_cwe else "n/a"),
        "",
        "## Findings per test (active)",
        "",
    ]
    for tid, n in sorted(per_test.items(), key=lambda x: -x[1]):
        buf.append(f"- {titles.get(tid, str(tid))} (test id {tid}): {n}")
    buf.append("")
    snap.write_text("\n".join(buf), encoding="utf-8")

    html_path = out / "dojo-metrics-rollup.html"
    tr_sev = "".join(f"<tr><td>{s}</td><td>{by_sev_open.get(s, 0)}</td></tr>" for s in sevs)
    tr_test = "".join(
        f"<tr><td>{titles.get(tid, tid)}</td><td>{n}</td></tr>"
        for tid, n in sorted(per_test.items(), key=lambda x: -x[1])
    )
    tr_cwe = "".join(f"<tr><td>CWE-{c}</td><td>{n}</td></tr>" for c, n in top_cwe)
    html_path.write_text(
        f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8"/>
<title>Engagement snapshot</title>
<style>
body {{ font-family: system-ui, sans-serif; margin: 2rem; color: #222; }}
h1 {{ font-size: 1.35rem; }}
table {{ border-collapse: collapse; margin: 1rem 0; min-width: 20rem; }}
th, td {{ border: 1px solid #ccc; padding: 0.35rem 0.55rem; text-align: left; }}
th {{ background: #eee; }}
.muted {{ color: #666; font-size: 0.9rem; }}
</style>
</head>
<body>
<h1>Juice Shop / Labs Security Testing</h1>
<p class="muted">Pulled {date.today().isoformat()} from the API (not the built-in Dojo report wizard).</p>
<h2>Active by severity</h2>
<table><thead><tr><th>Severity</th><th>Count</th></tr></thead><tbody>{tr_sev}</tbody></table>
<p><b>Verified (active):</b> {n_verified} &nbsp; <b>Mitigated:</b> {n_mitigated} &nbsp; <b>SLA ≤14d:</b> {sla_14}</p>
<h2>Active per import</h2>
<table><thead><tr><th>Test</th><th>Count</th></tr></thead><tbody>{tr_test}</tbody></table>
<h2>Top CWE (&gt;0)</h2>
<table><thead><tr><th>CWE</th><th>Count</th></tr></thead><tbody>{tr_cwe or "<tr><td colspan='2'>n/a</td></tr>"}</tbody></table>
</body>
</html>
""",
        encoding="utf-8",
    )

    print(csv_path, len(rows), "rows")
    print(snap)
    print(html_path)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
