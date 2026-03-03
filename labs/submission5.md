# Lab 5 — SAST & DAST of OWASP Juice Shop

**Target:** `bkimminich/juice-shop:v19.0.0`

---

## Task 1 — SAST with Semgrep

### Commands

```bash
mkdir -p labs/lab5/{semgrep,zap,nuclei,nikto,sqlmap,analysis,scripts}
git clone https://github.com/juice-shop/juice-shop.git --depth 1 --branch v19.0.0 labs/lab5/semgrep/juice-shop

docker run --rm \
  -v "$(pwd)/labs/lab5/semgrep/juice-shop":/src \
  -v "$(pwd)/labs/lab5/semgrep":/output \
  semgrep/semgrep:latest \
  semgrep --config=p/security-audit --config=p/owasp-top-ten \
  --json --output=/output/semgrep-results.json /src

docker run --rm \
  -v "$(pwd)/labs/lab5/semgrep/juice-shop":/src \
  -v "$(pwd)/labs/lab5/semgrep":/output \
  semgrep/semgrep:latest \
  semgrep --config=p/security-audit --config=p/owasp-top-ten \
  --text --output=/output/semgrep-report.txt /src
```

### SAST Tool Effectiveness

Semgrep ran 140 rules on 1 014 files and returned **25 findings** (7 ERROR, 18 WARNING). Backend TypeScript route handlers had the densest coverage — that's where the real vulnerabilities are. Frontend Angular templates produced a few unquoted-attribute warnings.

Vulnerability types found:
- **SQL Injection** (6) — unsanitized request params passed into Sequelize queries in `login.ts`, `search.ts`, and several challenge routes
- **Code injection via `eval`** (1) — Express request data flows directly into `eval()` in `userProfile.ts`
- **Hardcoded JWT secret** (1) — static signing key in `insecurity.ts`
- **Unsafe `res.sendFile`** (4) — user-influenced path passed to `sendFile()` in file-serving routes
- **Open redirect** (2) — unvalidated destination in `redirect.ts`
- **Directory listing** (4) — directories exposed via `express.static()` in `server.ts`
- **XSS vectors** (6) — unquoted attributes in Angular templates and raw HTML rendered in chatbot

### Top 5 Critical Findings

| # | Vulnerability type | File | Line | Severity |
|---|---|---|---|---|
| 1 | SQL Injection (Sequelize, user input) | `routes/login.ts` | 34 | ERROR |
| 2 | SQL Injection (Sequelize, user input) | `routes/search.ts` | 23 | ERROR |
| 3 | Code injection via `eval` (request data) | `routes/userProfile.ts` | 62 | ERROR |
| 4 | SQL Injection (union-based challenge) | `codefixes/unionSqlInjectionChallenge_1.ts` | 6 | ERROR |
| 5 | Hardcoded JWT signing secret | `lib/insecurity.ts` | 56 | WARNING |

---

## Task 2 — DAST with Multiple Tools

```bash
docker run -d --name juice-shop-lab5 -p 3000:3000 bkimminich/juice-shop:v19.0.0
sleep 10
curl -s http://localhost:3000 | head -n 3
```

### ZAP Unauthenticated Scan

```bash
docker run --rm --network host \
  -v "$(pwd)/labs/lab5/zap":/zap/wrk/:rw \
  zaproxy/zap-stable:latest \
  zap-baseline.py -t http://localhost:3000 \
  -r report-noauth.html -J zap-report-noauth.json
```

12 alerts: 0 High, 1 Medium (CSP not set), rest Low/Info.

### ZAP Authenticated Scan

```bash
# Verify auth endpoint works
curl -s -X POST http://localhost:3000/rest/user/login \
  -H 'Content-Type: application/json' \
  -d '{"email":"admin@juice-sh.op","password":"admin123"}' | jq '.authentication.token'

# Authenticated scan via Automation Framework
docker run --rm --network host \
  -v "$(pwd)/labs/lab5":/zap/wrk/:rw \
  zaproxy/zap-stable:latest \
  zap.sh -cmd -autorun /zap/wrk/scripts/zap-auth.yaml
```

### Authenticated vs Unauthenticated Comparison

| Metric | Unauthenticated | Authenticated |
|--------|----------------:|---------------:|
| Total alerts | 12 | 8 |
| High | 0 | 1 |
| Medium | 1 | 2 |
| URLs found | ~30 | 395 (49 spider + 346 AJAX) |

The AJAX spider ran after login and found 346 URLs — more than 10x the unauthenticated baseline. The active scan then confirmed SQL Injection (High) against an endpoint the baseline never reached.

Admin/authenticated endpoints discovered only after login:
- `http://localhost:3000/rest/admin/application-configuration`
- `http://localhost:3000/rest/user/whoami`
- `http://localhost:3000/rest/basket/*`
- `http://localhost:3000/rest/order-history`

Authenticated scanning matters because the bulk of any web app's attack surface lives behind a login — admin panels, user data, payment flows. A baseline scan gives you a partial picture at best.

### Nuclei

```bash
docker run --rm --network host \
  -v "$(pwd)/labs/lab5/nuclei":/app \
  projectdiscovery/nuclei:latest \
  -u http://localhost:3000 -jsonl -o /app/nuclei-results.json
```

24 findings: 1 Medium, 23 Info. The Medium finding was Prometheus `/metrics` endpoint exposed without authentication — leaks internal runtime stats. Info findings: Swagger API docs public at `/api-docs/swagger.yaml`, `X-Recruiting` header present.

### Nikto

```bash
docker run --rm --network host \
  -v "$(pwd)/labs/lab5/nikto":/tmp \
  frapsoft/nikto:latest \
  -h http://localhost:3000 -o /tmp/nikto-results.txt
```

14 findings — all server config issues: ETag leaks inodes, `Access-Control-Allow-Origin: *`, DELETE/PUT methods open globally, `/ftp/` directory accessible (HTTP 200, also in `robots.txt`), `/public/` browsable.

### SQLmap

```bash
# Search endpoint — boolean-based blind
sqlmap -u 'http://localhost:3000/rest/products/search?q=*' \
  --dbms=sqlite --batch --level=3 --risk=2 \
  --technique=B --threads=5 --output-dir=labs/lab5/sqlmap

# Login endpoint — boolean + time-based, with dump
sqlmap -u 'http://localhost:3000/rest/user/login' \
  --data '{"email":"*","password":"test"}' \
  --method POST --headers='Content-Type: application/json' \
  --dbms=sqlite --batch --level=5 --risk=3 \
  --technique=BT --threads=5 --output-dir=labs/lab5/sqlmap --dump
```

Both endpoints confirmed injectable. SQLmap dumped the database through boolean-based blind injection on the search endpoint — extracted `Baskets`, `Feedbacks`, and `Users` tables including bcrypt password hashes.

### Tool Comparison Matrix

| Tool | Findings | Severity breakdown | Best use case |
|------|----------|--------------------|---------------|
| ZAP (authenticated) | 8 | 1 High, 2 Med, 3 Low, 2 Info | Full web app scan with auth and active exploitation |
| Nuclei | 24 | 1 Med, 23 Info | Quick CVE/template matching, tech fingerprinting |
| Nikto | 14 | Server config issues | Web server misconfiguration checks |
| SQLmap | 2 endpoints | Critical — SQLi confirmed + DB dump | Targeted SQL injection depth testing |

### Tool-Specific Strengths

**ZAP** combines crawling, passive analysis, and active attack in one run, and it's the only tool here that supports authentication. That's what made it find the SQL Injection High-risk finding — it got past the login and hit endpoints the other tools never saw. Best for staging environment testing where you need a full picture.  
*Example:* SQL Injection (High) confirmed in an authenticated REST endpoint.

**Nuclei** was the fastest — done in under 3 minutes. It's template-driven, so it's good for checking known issues and technology exposure rather than doing deep fuzzing. Found the open Prometheus metrics endpoint and confirmed the Swagger spec is public.  
*Example:* `GET /metrics` returns Prometheus data without any auth.

**Nikto** only cares about the server config layer — HTTP headers, exposed directories, allowed methods. It flagged the `*` CORS policy and the `/ftp/` directory, which none of the other tools specifically called out.  
*Example:* `/ftp/` returns HTTP 200, publicly browsable.

**SQLmap** does one thing but goes deep. It confirmed injection in both endpoints and extracted actual table data. No other tool produced real data exfiltration evidence.  
*Example:* Boolean-based blind SQLi in `?q=*`, Users table dumped.

---

## Task 3 — SAST/DAST Correlation

```bash
echo "=== SAST/DAST Correlation Report ===" > labs/lab5/analysis/correlation.txt
sast_count=$(jq '.results | length' labs/lab5/semgrep/semgrep-results.json 2>/dev/null || echo "0")
zap_total=$(jq '[.site[].alerts[]] | length' labs/lab5/zap/zap-report-auth.json 2>/dev/null)
nuclei_count=$(wc -l < labs/lab5/nuclei/nuclei-results.json)
nikto_count=$(grep -c '^\+' labs/lab5/nikto/nikto-results.txt)
sqlmap_count=$(tail -n +2 labs/lab5/sqlmap/results-*.csv | grep -v '^$' | wc -l)
```

Full output: `labs/lab5/analysis/correlation.txt`

### SAST vs DAST

| Approach | Tool | Findings |
|---|---|---:|
| SAST | Semgrep | 25 |
| DAST | ZAP | 8 |
| DAST | Nuclei | 24 |
| DAST | Nikto | 14 |
| DAST | SQLmap | 2 |
| DAST total | | ~48 |

DAST combined found roughly twice as many results as SAST — but they cover very different ground with minimal overlap.

**Found only by SAST:**
- Hardcoded JWT secret in `insecurity.ts` — only visible in source, no observable runtime signal
- `eval()` with request data in `userProfile.ts` — hard to reliably trigger through automated HTTP scanning
- Open redirect logic in `redirect.ts` — DAST hit the endpoint but couldn't distinguish user-controlled from fixed redirects

**Found only by DAST:**
- Missing CSP header — a server response config, doesn't exist in application code
- `/ftp/` publicly accessible — server-level exposure, nothing to scan statically
- Prometheus `/metrics` open — infrastructure config issue
- `Access-Control-Allow-Origin: *` — set in Express middleware, not reliably caught by Semgrep rules

SAST reads the code and catches things that happen before the app runs — hardcoded values, dangerous patterns, logic flaws in paths that automated scanning might never exercise. DAST works against the live application and finds everything that results from how the code was deployed: server headers, exposed directories, real exploitability. Neither replaces the other.
