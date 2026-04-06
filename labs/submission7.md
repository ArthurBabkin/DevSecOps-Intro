# Lab 7 — Container Security: Image Scanning & Deployment Hardening

**Target:** `bkimminich/juice-shop:v19.0.0`

---

## Task 1 — Image Vulnerability & Configuration Analysis

### Commands

```bash
mkdir -p labs/lab7/{scanning,hardening,analysis}

docker scout cves bkimminich/juice-shop:v19.0.0 | tee labs/lab7/scanning/scout-cves.txt
docker scout recommendations bkimminich/juice-shop:v19.0.0 | tee labs/lab7/scanning/scout-recommendations.txt

docker run --rm -v /var/run/docker.sock:/var/run/docker.sock \
  goodwithtech/dockle:latest bkimminich/juice-shop:v19.0.0 | tee labs/lab7/scanning/dockle-results.txt
```

### Vulnerability Summary

Scout found **104 vulnerabilities** in 44 packages -- 11 critical, 55 high, 28 medium, 3 low, 7 unspecified.

### Top 5 Critical Vulnerabilities

| # | CVE | Package | Impact | Fix |
|---|-----|---------|--------|-----|
| 1 | CVE-2026-22709 | `vm2@3.9.17` | sandbox escape | upgrade to 3.10.2 |
| 2 | CVE-2023-37903 | `vm2@3.9.17` | OS command injection via vm2 | no fix available |
| 3 | CVE-2023-37466 | `vm2@3.9.17` | arbitrary code execution | upgrade to 3.10.0 |
| 4 | CVE-2025-55130 | `node@22.18.0` | runtime vulnerability | upgrade to 22.22.0 |
| 5 | CVE-2019-10744 | `lodash@2.4.2` | prototype pollution | upgrade to 4.17.12 |

Also critical: `jsonwebtoken@0.4.0` (CVE-2015-9235, JWT bypass) and `crypto-js@3.3.0` (CVE-2023-46233, broken hash algorithm).

vm2 is the worst part -- three separate critical CVEs. There are patches for some of them (3.10.0, 3.10.2), but vm2 has been abandoned since mid-2023 and new CVEs keep showing up, so patching it is not a long-term fix. The package needs to be replaced.

### Snyk Comparison

```bash
docker run --rm \
  -e SNYK_TOKEN \
  -v /var/run/docker.sock:/var/run/docker.sock \
  snyk/snyk:docker snyk test --docker bkimminich/juice-shop:v19.0.0 --severity-threshold=high \
  | tee labs/lab7/scanning/snyk-results.txt
```

Snyk scanned 2 projects (OS packages + npm manifest) and found 63 issues in 985 dependencies.

| Project | Deps | Issues | Critical | High |
|---------|------|--------|----------|------|
| OS packages (deb) | 10 | 8 | 1 | 7 |
| npm (`package.json`) | 975 | 55 | 5 | 50 |

Snyk flagged some things as critical that Scout didn't highlight:

| Package | Issue |
|---------|-------|
| `handlebars@4.7.7` | 3x type confusion -- RCE via template rendering |
| `multer@1.4.5-lts.2` | uncaught exception -- DoS on file upload |
| `marsdb@0.6.11` | arbitrary code injection, no fix available |

Main priorities were the same in both: `vm2` and `node@22.18.0`. Where they differ is presentation -- Scout gives you CVE IDs and CVSS scores right away, Snyk shows the full chain from the top-level package down to what introduced the vulnerability, and prints the upgrade command inline. Snyk was more useful for digging into the npm deps, Scout was simpler to read for the OS layer.

### Dockle Configuration Findings

No FATAL or WARN issues. Three INFO findings:

| Check | Finding | Why it matters |
|-------|---------|---------------|
| CIS-DI-0005 | `DOCKER_CONTENT_TRUST` not set | pulled image could be tampered and you wouldn't know |
| CIS-DI-0006 | no `HEALTHCHECK` | orchestrators can't detect a crashed process inside the container |
| DKL-LI-0003 | `.DS_Store` files in `node_modules` | extra files in the image, slightly bigger attack surface |

### Security Posture Assessment

The image runs as root (UID 0) -- there's no `USER` instruction in the Dockerfile. I tried running it with `--user=1000:1000` but it crashes on startup because the app writes to directories owned by root.

Things to fix: replace `vm2`, upgrade the base Node image, add a `HEALTHCHECK`, and rebuild with a non-root user (file ownership needs to be fixed in the Dockerfile first).

---

## Task 2 — Docker Host Security Benchmarking

### Commands

```bash
docker run --rm --net host --pid host --userns host --cap-add audit_control \
  -e DOCKER_CONTENT_TRUST=$DOCKER_CONTENT_TRUST \
  -v /etc:/etc:ro \
  -v /var/lib:/var/lib:ro \
  -v /var/run/docker.sock:/var/run/docker.sock:ro \
  -v /usr/lib/systemd:/usr/lib/systemd:ro \
  --label docker_bench_security \
  docker/docker-bench-security | tee labs/lab7/hardening/docker-bench-results.txt
```

### Summary Statistics

| Result | Count |
|--------|------:|
| PASS | 24 |
| WARN | 32 |
| INFO | 78 |
| NOTE | 7 |
| FAIL | 0 |
| **Score** | **8 / 74** |

No FAILs, all actionable issues are WARNs.

### Analysis of Warnings

**Host config (1.5, 1.6, 1.7, 1.11):** auditd rules are missing for the Docker binary and config dirs. If someone modifies `/etc/docker` or `daemon.json`, there's no audit trail for it.

**Daemon config -- key warnings:**

| Check | Issue | Fix |
|-------|-------|-----|
| 2.1 | ICC not restricted on default bridge | `"icc": false` in `daemon.json` |
| 2.6 | TCP socket open without TLS | disable TCP or use mutual TLS |
| 2.8 | user namespace remapping off | `"userns-remap": "default"` in `daemon.json` |
| 2.12 | no centralized logging | `--log-driver=journald` or forward to SIEM |
| 2.18 | `no-new-privileges` not enforced globally | `"no-new-privileges": true` in `daemon.json` |

**Images (4.6):** 10 of 17 local images have no `HEALTHCHECK`, including juice-shop.

The most useful fix is 2.8 (user namespace remapping) -- even if a container breaks out, the process runs as an unprivileged user on the host.

---

## Task 3 — Deployment Security Configuration Analysis

### Commands

```bash
# Profile 1 -- Default
docker run -d --name juice-default -p 3001:3000 bkimminich/juice-shop:v19.0.0

# Profile 2 -- Hardened
docker run -d --name juice-hardened -p 3002:3000 \
  --cap-drop=ALL \
  --security-opt=no-new-privileges \
  --memory=512m \
  --cpus=1.0 \
  bkimminich/juice-shop:v19.0.0

# Profile 3 -- Production
# 'seccomp=builtin' is the name Docker 28 uses for its built-in seccomp profile
# (docker info shows "name=seccomp,profile=builtin"). 'seccomp=default' failed
# with "no such file or directory" on this setup.
docker run -d --name juice-production -p 3003:3000 \
  --cap-drop=ALL --cap-add=NET_BIND_SERVICE \
  --security-opt=no-new-privileges \
  --security-opt=seccomp=builtin \
  --memory=512m --memory-swap=512m \
  --cpus=1.0 \
  --pids-limit=100 \
  --restart=on-failure:3 \
  bkimminich/juice-shop:v19.0.0

sleep 15

docker stats --no-stream \
  --format "table {{.Name}}\t{{.CPUPerc}}\t{{.MemUsage}}\t{{.MemPerc}}" \
  juice-default juice-hardened juice-production

docker stop juice-default juice-hardened juice-production
docker rm juice-default juice-hardened juice-production
```

### Configuration Comparison

| Setting | Default | Hardened | Production |
|---------|---------|----------|------------|
| `--cap-drop` | none | ALL | ALL |
| `--cap-add` | -- | -- | NET_BIND_SERVICE |
| `--security-opt` | none | no-new-privileges | no-new-privileges, seccomp=builtin |
| `--memory` | unlimited | 512 MiB | 512 MiB |
| `--memory-swap` | unlimited | 1024 MiB (default 2×) | 512 MiB |
| `--cpus` | unlimited | 1.0 | 1.0 |
| `--pids-limit` | unlimited | unlimited | 100 |
| `--restart` | no | no | on-failure:3 |
| HTTP response | 200 ✓ | 200 ✓ | 200 ✓ |
| Memory in use | 93.9 MiB | 87.3 MiB | 84.0 MiB |

All three returned HTTP 200, so the security restrictions didn't break the app.

### Security Measure Analysis

**a) `--cap-drop=ALL` / `--cap-add=NET_BIND_SERVICE`**

Linux capabilities are how Linux breaks up the traditional "root can do everything" model into smaller pieces. Instead of root being one all-or-nothing privilege, you have individual capabilities: `CAP_NET_RAW` lets you open raw sockets (so you can sniff packets), `CAP_SYS_MODULE` lets you load kernel modules, `CAP_PTRACE` lets you attach a debugger to other processes, etc. A container gets a default set of these -- not everything, but still quite a lot.

Dropping ALL means a compromised container process can't do any of that even if it's running as root inside the container. The main trade-off is that some apps break because they genuinely need certain capabilities (like `CAP_NET_BIND_SERVICE` to bind to port 80). We add that one back. Juice Shop doesn't actually need it (it runs on 3000), but it's normally included for apps that might get deployed on 80/443.

**b) `--security-opt=no-new-privileges`**

Blocks the process from gaining extra privileges via setuid/setgid binaries. Without this flag you could just `exec` into the container, find a setuid binary like `su`, and become root. With it, setuid bits are ignored. Almost no real app needs setuid, so there's basically no downside.

**c) `--memory=512m` / `--cpus=1.0`**

Without memory limits a single container can allocate until the host OOM-kills everything. This matters both for accidental leaks and for intentional resource exhaustion attacks. `--cpus=1.0` works through cgroup quota -- Docker stores it as `NanoCpus=1000000000` internally, which means the container gets at most 100% of one core.

From the test: Juice Shop used about 94 MiB and under 1% CPU at idle, so 512 MiB / 1 CPU should be fine. Setting them too low would cause the app to get OOM-killed under normal traffic, so you have to measure first before picking values.

**d) `--pids-limit=100`**

Protects against fork bombs. A fork bomb is a script that just keeps forking itself (`:(){ :|:& };:` in bash) until the system runs out of process IDs and freezes. With a PID limit the container stops being able to spawn processes once it hits the cap, but the host is fine. Juice Shop ran with 11 PIDs, so 100 leaves room for spikes without being too loose.

**e) `--restart=on-failure:3`**

Restarts the container if it crashes (non-zero exit code), but only up to 3 times. After that it stops and stays stopped.

| Policy | What it does |
|--------|-------------|
| `no` | never auto-restarts |
| `on-failure:N` | restarts on crash, gives up after N times |
| `unless-stopped` | always restarts unless you explicitly ran `docker stop` |
| `always` | like `unless-stopped` but also restarts after daemon restart even if you previously stopped it |

`on-failure:3` is safer than `unless-stopped` because it fails loudly -- if something keeps crashing, after 3 restarts the container goes down for good and your monitoring fires. `unless-stopped` would just keep restarting forever, which hides the problem.

### Critical Thinking Questions

**1. Which profile for development?**

Default. Developers need to attach debuggers, install packages, bind-mount source code -- a lot of this breaks under `--cap-drop=ALL`. The security trade-off is fine on a local machine.

**2. Which profile for production?**

Production. All restrictions were tested and the app still works, resource limits protect other services on the host, and the restart policy handles crashes without hiding them.

**3. What real-world problem do resource limits solve?**

The noisy neighbor problem -- one container with a memory leak (or being actively exploited for cryptomining) can't take down everything else on the host. CPU limits also stop an attacker from using the container for mining after they get in.

**4. What actions are blocked in Production vs Default after exploitation?**

In Default an attacker with RCE can sniff raw traffic (`CAP_NET_RAW`), load kernel modules (`CAP_SYS_MODULE`), escalate via setuid binaries, and run a fork bomb. In Production all of that is blocked by `--cap-drop=ALL`, `--no-new-privileges`, and `--pids-limit=100`.

**5. What additional hardening would you add?**

Rebuild the image with a non-root user (fix file ownership first), write a custom seccomp profile to block syscalls like `ptrace` and `mount`, add `--read-only` with `tmpfs` for paths the app writes to, and restrict outbound network with firewall rules or network policies.
