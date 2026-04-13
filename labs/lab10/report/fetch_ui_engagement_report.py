#!/usr/bin/env python3
import os
import re
import sys

import requests


def main() -> int:
    base = os.environ.get("DD_BASE", "http://localhost:8080").rstrip("/")
    user = os.environ.get("DD_USER", "admin")
    password = os.environ.get("DD_PASSWORD", "")
    if not password:
        print("need DD_PASSWORD (admin UI password)", file=sys.stderr)
        return 1
    eid = os.environ.get("DD_ENGAGEMENT_ID", "1")
    out = os.environ.get("DD_REPORT_OUT", "")
    if not out:
        here = os.path.dirname(os.path.abspath(__file__))
        out = os.path.join(here, "dojo-report.html")

    s = requests.Session()
    r = s.get(f"{base}/login", timeout=30)
    r.raise_for_status()
    m = re.search(r'name="csrfmiddlewaretoken" value="([^"]+)"', r.text)
    if not m:
        print("no csrf on /login", file=sys.stderr)
        return 1
    tok = m.group(1)
    p = s.post(
        f"{base}/login",
        data={
            "csrfmiddlewaretoken": tok,
            "username": user,
            "password": password,
        },
        headers={"Referer": f"{base}/login"},
        timeout=30,
        allow_redirects=True,
    )
    p.raise_for_status()

    rep = s.get(f"{base}/engagement/{eid}/report", timeout=120)
    rep.raise_for_status()
    if "Login" in rep.text and "csrfmiddlewaretoken" in rep.text and rep.text.count("id_password") > 0:
        print("still on login page, auth failed?", file=sys.stderr)
        return 1

    with open(out, "w", encoding="utf-8") as f:
        f.write(rep.text)
    print(out, len(rep.text))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
