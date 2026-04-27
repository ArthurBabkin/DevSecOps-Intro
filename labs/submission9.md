# Lab 9 — Monitoring & Compliance: Falco + Conftest

**Runtime helper:** `alpine:3.19` container (`lab9-helper`)

---

## Task 1 — Falco runtime detection

### What I ran

```bash
mkdir -p labs/lab9/falco/{rules,logs} labs/lab9/analysis

docker run -d --name lab9-helper alpine:3.19 sleep 1d

docker run -d --name falco \
  --privileged \
  -v /proc:/host/proc:ro \
  -v /boot:/host/boot:ro \
  -v /lib/modules:/host/lib/modules:ro \
  -v /usr:/host/usr:ro \
  -v /var/run/docker.sock:/host/var/run/docker.sock \
  -v "$(pwd)/labs/lab9/falco/rules":/etc/falco/rules.d:ro \
  falcosecurity/falco:latest \
  falco -U -o json_output=true -o time_format_iso_8601=true
```

Custom rule file: `labs/lab9/falco/rules/custom-rules.yaml` (from the lab text).

Triggers:

```bash
docker exec lab9-helper /bin/sh -lc 'echo hello-from-shell'
docker exec --user 0 lab9-helper /bin/sh -lc 'echo boom > /usr/local/bin/drift.txt'
docker exec --user 0 lab9-helper /bin/sh -lc 'echo custom-test > /usr/local/bin/custom-rule.txt'
```

Then `falcosecurity/event-generator:latest run syscall` (privileged) to generate more events.

Full JSON log: `labs/lab9/falco/logs/falco.log`

### Baseline alerts (from the log)

On my machine `docker exec` did not produce the classic "Terminal shell in container" line for the first echo (no TTY, and a lot of noise from `runc` / memfd). What showed up clearly:

- **Fileless execution via memfd_create** — shows up a lot when Docker runs `runc` from a memfd; looks bad in the UI but is basically how `docker exec` works here. You would filter or tune that in a real cluster so it does not alert on every admin exec.
- **Run shell untrusted** — from event-generator: `sh -c ls > /dev/null` with a weird parent process (Falco thinks the shell is suspicious).
- **Read sensitive file untrusted** / **Directory traversal monitored file read** — reads touching `/etc/shadow` from the generator (credential access style behavior).
- Lots of other generator rules: PTRACE, netcat RCE pattern, execution from `/dev/shm`, AWS credential search, **Drop and execute new binary in container**, etc.

Output is one JSON object per line; rules carry MITRE tags in the log.

### Custom rule: `Write Binary Under UsrLocalBin`

The rule flags create/open-for-write under `/usr/local/bin/` inside a container (`container.id != host`). That is the kind of thing you see when someone drops a file next to real binaries (drift or malware). Here it fired twice because I wrote two different filenames there as root.

It would be noisy if some job legitimately installed into `/usr/local/bin` at runtime — then you whitelist by image or namespace in Falco.

Falco loaded the file without errors (`custom-rules.yaml | schema validation: ok`). Writes to `drift.txt` and `custom-rule.txt` both hit my rule.

The lab says that write should fire **both** the stock drift-style rule and the custom one. In `falco.log`, for those two files, the JSON field `"rule"` is only `Write Binary Under UsrLocalBin` — no second built-in rule line for the same syscall. Either the default ruleset did not match this path/container combo on my Falco version, or the event was only emitted once per open. So I still validated the custom rule; stock vs custom overlap is environment-specific and worth tuning in a real deploy.

### Environment note

Startup printed libbpf warnings about some tracepoints (TOCTOU helpers). Falco still ran and emitted alerts. This was on Docker (Linux VM under the hood).

---

## Task 2 — Conftest (Rego) on manifests

### Manifest comparison (K8s)

| Topic | `juice-unhardened.yaml` | `juice-hardened.yaml` |
|--------|-------------------------|------------------------|
| Image tag | `bkimminich/juice-shop:latest` | `bkimminich/juice-shop:v19.0.0` |
| securityContext | missing | `runAsNonRoot`, `allowPrivilegeEscalation: false`, `readOnlyRootFilesystem: true`, `capabilities.drop: [ALL]` |
| Resources | none | requests + limits for CPU and memory |
| Probes | none | `readinessProbe` and `livenessProbe` on HTTP `/` |

### Policy packages

- `k8s-security.rego` — `deny` on :latest, missing `securityContext` fields (non-root, no priv esc, read-only root), missing `capabilities.drop: ALL`, missing resource requests/limits; `warn` on missing probes.
- `compose-security.rego` — `deny` on missing `user`, `read_only`, `cap_drop: ALL`; `warn` on missing `no-new-privileges:true`.

On the unhardened Deployment there is no `securityContext` block at all. The `deny` that checks `c.securityContext.capabilities.drop` never fires because `c.securityContext.capabilities` is undefined in Rego — so Conftest does **not** list "must drop ALL capabilities" as an eighth failure. You still see that check on the hardened manifest where `securityContext` exists.

### Results (saved under `labs/lab9/analysis/`)

**Unhardened K8s** — **8 FAIL, 2 WARN** (`conftest-unhardened.txt`). Eight `deny` lines, matching the table below (grouped by topic, not necessarily print order):

| What Conftest reported | Why it matters |
|------------------------|----------------|
| missing all four of `resources.requests/limits` cpu and memory | No resource quotas on the pod |
| must set `allowPrivilegeEscalation: false` | Easier privesc (e.g. setuid) |
| must set `readOnlyRootFilesystem: true` | Writable root FS helps an attacker persist files |
| must set `runAsNonRoot: true` | Process likely runs as root in the container |
| uses disallowed `:latest` tag | Deploy is not pinned to a digest |

Warnings: no `readinessProbe` / `livenessProbe`.

**Hardened K8s** — **30 tests, 30 passed, 0 warnings** (`conftest-hardened.txt`). The YAML changes above satisfy every `deny` and the probe `warn` rules.

**Compose** (`juice-compose.yml`) — **15 tests, 15 passed** (`conftest-compose.txt`). The file already has `user: "10001:10001"`, `read_only: true`, `tmpfs` for `/tmp`, `cap_drop: [ALL]`, and `security_opt: no-new-privileges:true`, so it satisfies the compose Rego checks.

---

## Cleanup

```bash
docker rm -f falco lab9-helper 2>/dev/null || true
```

(Containers were removed after capturing logs.)
