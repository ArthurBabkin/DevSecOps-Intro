# Lab 11 — Nginx reverse proxy (Juice Shop)

Date: 2026-04-19. Stack files: `labs/lab11/docker-compose.yml`, `labs/lab11/reverse-proxy/nginx.conf`. I generated a self-signed cert into `labs/lab11/reverse-proxy/certs/` like in `labs/lab11.md` (that path is gitignored — recreate the cert before `docker compose up`).

Outputs are in `labs/lab11/analysis/`: `docker-compose-ps.txt`, `headers-http.txt`, `headers-https.txt`, `testssl.txt`, `rate-limit-test.txt`, `access-log-429-sample.txt`.

## Task 1 — Reverse proxy setup

**Why use a reverse proxy for security**

The proxy is one place where you can end TLS, add security headers, filter or shape traffic, and log requests. The app behind it does not need to be exposed on the host network with its own port, and you can change policy in one config instead of touching the application.

**Why not publish the app port**

If Juice Shop listened on the host (for example port 3000), clients could talk to it directly and skip Nginx (no shared headers, limits, or TLS policy). In compose only Nginx maps ports to the host; the Juice container only has an internal port.

**`docker compose ps`**

```text
NAME            IMAGE                           COMMAND                  SERVICE   CREATED          STATUS          PORTS
lab11-juice-1   bkimminich/juice-shop:v19.0.0   "/nodejs/bin/node /j…"   juice     12 seconds ago   Up 11 seconds   3000/tcp
lab11-nginx-1   nginx:stable-alpine             "/docker-entrypoint.…"   nginx     12 seconds ago   Up 11 seconds   0.0.0.0:8080->8080/tcp, [::]:8080->8080/tcp, 80/tcp, 0.0.0.0:8443->8443/tcp, [::]:8443->8443/tcp
```

Juice has `3000/tcp` only (no `0.0.0.0:` mapping). Nginx has `8080` and `8443` on the host.

**HTTP check**

`curl -s -o /dev/null -w "HTTP %{http_code}\n" http://localhost:8080/` → **308** (redirect to HTTPS). Same as the lab expects.

## Task 2 — Security headers

After `cd labs/lab11`:

- `curl -sI http://localhost:8080/ | tee analysis/headers-http.txt`
- `curl -skI https://localhost:8443/ | tee analysis/headers-https.txt`

**Headers from `headers-https.txt` (the important ones)**

```http
strict-transport-security: max-age=31536000; includeSubDomains; preload
x-frame-options: DENY
x-content-type-options: nosniff
referrer-policy: strict-origin-when-cross-origin
permissions-policy: camera=(), geolocation=(), microphone=()
cross-origin-opener-policy: same-origin
cross-origin-resource-policy: same-origin
content-security-policy-report-only: default-src 'self'; img-src 'self' data:; script-src 'self' 'unsafe-inline' 'unsafe-eval'; style-src 'self' 'unsafe-inline'
```

Juice Shop also sends some of its own headers (you can see extra lines in the full file). Nginx is configured to hide several upstream security headers so the proxy version wins.

**What each header is for**

- **X-Frame-Options** — makes clickjacking harder; `DENY` means the page should not be shown in a frame on another site.
- **X-Content-Type-Options** — `nosniff` reduces MIME sniffing so the browser is less likely to run content as a wrong type.
- **Strict-Transport-Security (HSTS)** — tells the browser to use HTTPS for this host for a long time; helps against sslstrip-style attacks if the user already reached HTTPS once.
- **Referrer-Policy** — controls how much of the URL is sent in the `Referer` header when you leave the page (less data leaked to other sites).
- **Permissions-Policy** — turns off camera / geolocation / microphone by default for this document.
- **COOP / CORP** — COOP controls how the page interacts with other windows; CORP limits cross-origin embedding/loading of the response. Both are set to `same-origin` here.
- **CSP-Report-Only** — does not block yet, only reports; safer for a JS-heavy app like Juice Shop while you tune policy.

**HSTS only on HTTPS**

In `headers-http.txt` there is **no** `Strict-Transport-Security` line. HSTS shows up on the HTTPS response only, which matches `nginx.conf` (HSTS is in the TLS server block, not on the HTTP redirect).

## Task 3 — TLS, HSTS, rate limits, timeouts

### testssl

Still in `labs/lab11/`, on macOS with Docker Desktop:

`docker run --rm drwetter/testssl.sh:latest https://host.docker.internal:8443 | tee analysis/testssl.txt`

**Protocols:** SSLv2, SSLv3, TLS 1.0, TLS 1.1 are not offered. TLS 1.2 and TLS 1.3 are offered.

**Ciphers (from the scan, not the full list):**

- TLS 1.2: `ECDHE-RSA-AES256-GCM-SHA384`, `ECDHE-RSA-AES128-GCM-SHA256`
- TLS 1.3: `TLS_AES_256_GCM_SHA384`, `TLS_CHACHA20_POLY1305_SHA256`, `TLS_AES_128_GCM_SHA256`

**Why TLS 1.2+ (and 1.3 is better)**

Older protocol versions are deprecated because of known weaknesses. TLS 1.2 is the usual minimum now. TLS 1.3 is newer and drops a lot of old handshake options.

**Warnings / problems in the output**

For a dev self-signed cert, testssl reports things like: self-signed chain (not trusted), hostname mismatch when using `host.docker.internal` vs `localhost` on the certificate, no OCSP/CRL, no stapling, no CT. The lab text says to expect that on localhost. The vuln checks I looked at (Heartbleed, ROBOT, SWEET32, etc.) were OK.

**HSTS**

testssl’s header probe for `/` is over **HTTPS**; it shows HSTS (365 days, includeSubDomains, preload), same as `curl -skI https://localhost:8443/`.

### Rate limiting on `/rest/user/login`

Lab loop (12 POSTs) saved in `analysis/rate-limit-test.txt`:

```text
401
401
401
401
401
429
429
429
429
429
429
429
```

The lab text says to compare 200s and 429s. Here: **0×200**, **5×401**, **7×429** — no successful login, so no 200s; 401 means Juice Shop rejected the password, then Nginx returned 429 when the zone limit was hit.

Config in `nginx.conf`: `limit_req_zone ... rate=10r/m` and `limit_req zone=login burst=5 nodelay` on `location = /rest/user/login`. Roughly **10 req/min per IP** with **burst 5**. Tighter limits stop more guessing but can block real users on shared IPs; looser limits are nicer for users and weaker against guessing.

### Timeouts (from `nginx.conf`) and trade-offs

`client_body_timeout` and `client_header_timeout` are both 10s — slow request bodies or headers time out so one client cannot hold connections open forever (slowloris-type risk). The downside is a very slow client on a bad network might hit the limit.

`proxy_read_timeout` is 30s (wait for Juice Shop to respond) and `proxy_send_timeout` is 30s (sending data to Juice Shop). Shorter values free workers faster if upstream hangs; too short and heavy pages might fail.

Nginx also sets `keepalive_timeout`, `send_timeout`, and `proxy_connect_timeout` elsewhere in the same file.

### `access.log` lines with 429

From `analysis/access-log-429-sample.txt`:

```text
192.168.117.1 - - [19/Apr/2026:12:37:58 +0000] "POST /rest/user/login HTTP/2.0" 429 162 "-" "curl/8.7.1" rt=0.000 uct=- urt=-
```

## Cleanup

```bash
cd labs/lab11 && docker compose down
```
