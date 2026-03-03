# Lab 4 — SBOM Generation & Software Composition Analysis

**Target:** `bkimminich/juice-shop:v19.0.0`

---

## Task 1 — SBOM Generation with Syft and Trivy

### Commands used

```bash
# Syft — native JSON
docker run --rm -v /var/run/docker.sock:/var/run/docker.sock \
  -v "$(pwd)":/tmp anchore/syft:latest \
  bkimminich/juice-shop:v19.0.0 -o syft-json=/tmp/labs/lab4/syft/juice-shop-syft-native.json

# Syft — human-readable table
docker run --rm -v /var/run/docker.sock:/var/run/docker.sock \
  -v "$(pwd)":/tmp anchore/syft:latest \
  bkimminich/juice-shop:v19.0.0 -o table=/tmp/labs/lab4/syft/juice-shop-syft-table.txt

# Trivy — JSON with all packages
docker run --rm -v /var/run/docker.sock:/var/run/docker.sock \
  -v "$(pwd)":/tmp aquasec/trivy:latest image \
  --format json --list-all-pkgs \
  --output /tmp/labs/lab4/trivy/juice-shop-trivy-detailed.json \
  bkimminich/juice-shop:v19.0.0

# Trivy — table
docker run --rm -v /var/run/docker.sock:/var/run/docker.sock \
  -v "$(pwd)":/tmp aquasec/trivy:latest image \
  --format table \
  --output /tmp/labs/lab4/trivy/juice-shop-trivy-table.txt \
  bkimminich/juice-shop:v19.0.0

# License extraction from Syft SBOM
jq -r '.artifacts[] | select(.licenses != null and (.licenses | length > 0)) | "\(.name) | \(.version) | \(.licenses | map(.value) | join(", "))"' \
  labs/lab4/syft/juice-shop-syft-native.json >> labs/lab4/syft/juice-shop-licenses.txt
```

### Package Type Distribution

| Package type | Syft | Trivy |
|---|---:|---:|
| npm | ~1 072 | ~1 068 |
| deb (OS) | ~62 | ~62 |
| binary | ~5 | ~5 |
| **Total** | **1 139** | **1 135** |

### Dependency Discovery Analysis

Both tools covered the same OS base (Debian 12) and npm tree. Syft found 4 more packages — it does a deeper binary inspection of filesystem layers on top of reading `package.json` manifests. Trivy's results come from its own layer analyzers combined with OS package DB queries. In practice the coverage is nearly identical for a Node.js image like this.

### License Discovery Analysis

Syft found **32** unique license types vs **28** for Trivy. The difference is that Syft preserves compound SPDX expressions (e.g. `MIT AND BSD-2-Clause`) as-is, while Trivy normalises them to a single canonical SPDX ID, losing the compound structure. For license compliance auditing, Syft's output is more precise. Full lists: `labs/lab4/syft/juice-shop-licenses.txt`, `labs/lab4/trivy/trivy-licenses.json`.

---

## Task 2 — Software Composition Analysis

### Commands used

```bash
# Grype — from Syft SBOM
docker run --rm -v "$(pwd)":/tmp anchore/grype:latest \
  sbom:/tmp/labs/lab4/syft/juice-shop-syft-native.json \
  -o json > labs/lab4/syft/grype-vuln-results.json

docker run --rm -v "$(pwd)":/tmp anchore/grype:latest \
  sbom:/tmp/labs/lab4/syft/juice-shop-syft-native.json \
  -o table > labs/lab4/syft/grype-vuln-table.txt

# Trivy — vuln + secret + license combined
docker run --rm -v /var/run/docker.sock:/var/run/docker.sock \
  -v "$(pwd)":/tmp aquasec/trivy:latest image \
  --format json --scanners vuln,secret,license \
  --output /tmp/labs/lab4/trivy/juice-shop-trivy-vuln.json \
  bkimminich/juice-shop:v19.0.0

# Trivy — secrets only (table)
docker run --rm -v /var/run/docker.sock:/var/run/docker.sock \
  -v "$(pwd)":/tmp aquasec/trivy:latest image \
  --scanners secret --format table \
  --output /tmp/labs/lab4/trivy/trivy-secrets.txt \
  bkimminich/juice-shop:v19.0.0

# Trivy — license compliance
docker run --rm -v /var/run/docker.sock:/var/run/docker.sock \
  -v "$(pwd)":/tmp aquasec/trivy:latest image \
  --scanners license --format json \
  --output /tmp/labs/lab4/trivy/trivy-licenses.json \
  bkimminich/juice-shop:v19.0.0
```

### SCA Tool Comparison

| Severity | Trivy | Grype |
|----------|------:|------:|
| CRITICAL | 10 | 11 |
| HIGH | 81 | 87 |
| MEDIUM | 34 | 33 |
| LOW | 18 | 3 |
| **Total** | **143** | **146** |

The totals are close but not identical. Grype uses NVD + GitHub Advisory DB and reports each affected package version as a separate match; Trivy uses its own curated database and tends to group OS-level advisories differently, which explains the gap in LOW counts especially.

### Top 5 Critical Vulnerabilities

| CVE | Package | CVSS | Remediation |
|-----|---------|-----:|-------------|
| CVE-2026-22709 | vm2 3.9.17 | 10.0 | vm2 is abandoned — migrate to `isolated-vm` |
| CVE-2023-32314 | vm2 3.9.17 | 10.0 | Same as above |
| CVE-2023-37466 | vm2 3.9.17 | 10.0 | Same as above |
| CVE-2025-15467 | libssl3 3.0.17 | 9.8 | Rebuild base image from a patched Debian 12 snapshot |
| CVE-2015-9235 | jsonwebtoken 0.1 / 0.4 | 9.8 | Upgrade to `jsonwebtoken` ≥ 9.0.0 |

### License Compliance Assessment

No copyleft (GPL/AGPL) packages with direct linking were flagged as high-risk. The dominant licenses are MIT and ISC across the npm tree. The main compliance risk is the sheer size of the dependency tree (~1 072 npm packages) — transitive license drift is easy to miss without automated scanning on every build.

### Secrets Scanning

Trivy found **4 secrets** baked into the image layers. These are intentional Juice Shop demo credentials (CTF challenges), so they're expected here. In any real image this would be a critical finding — secrets should never end up in a Docker layer.

---

## Task 3 — Toolchain Comparison: Syft+Grype vs Trivy

### Commands used

```bash
# Extract package lists for overlap analysis
jq -r '.artifacts[] | "\(.name)@\(.version)"' \
  labs/lab4/syft/juice-shop-syft-native.json | sort > labs/lab4/comparison/syft-packages.txt
jq -r '.Results[]?.Packages[]? | "\(.Name)@\(.Version)"' \
  labs/lab4/trivy/juice-shop-trivy-detailed.json | sort > labs/lab4/comparison/trivy-packages.txt

comm -12 labs/lab4/comparison/syft-packages.txt labs/lab4/comparison/trivy-packages.txt \
  > labs/lab4/comparison/common-packages.txt
comm -23 labs/lab4/comparison/syft-packages.txt labs/lab4/comparison/trivy-packages.txt \
  > labs/lab4/comparison/syft-only.txt
comm -13 labs/lab4/comparison/syft-packages.txt labs/lab4/comparison/trivy-packages.txt \
  > labs/lab4/comparison/trivy-only.txt

# CVE overlap
jq -r '.matches[]?.vulnerability.id' \
  labs/lab4/syft/grype-vuln-results.json | sort | uniq > labs/lab4/comparison/grype-cves.txt
jq -r '.Results[]?.Vulnerabilities[]?.VulnerabilityID' \
  labs/lab4/trivy/juice-shop-trivy-vuln.json | sort | uniq > labs/lab4/comparison/trivy-cves.txt
```

### Accuracy Analysis

| Metric | Count |
|--------|------:|
| Packages detected by Syft | 1 139 |
| Packages detected by Trivy | 1 135 |
| Common packages (name@version exact match) | 1 126 |
| Syft-only | 13 |
| Trivy-only | 9 |
| Unique CVE IDs found by Grype | 95 |
| Unique CVE IDs found by Trivy | 91 |
| CVE IDs reported by both | 26 |

Package overlap is very high (99%). The small discrepancies are binaries and some edge-case packages where the two tools disagree on the version string format.

The CVE ID overlap looks low (26 shared IDs out of ~160 unique), but this is mostly a labelling artefact — Grype uses `GHSA-*` identifiers from the GitHub Advisory DB for many findings that Trivy tracks only under `CVE-*`, so the same vulnerability appears under a different ID in each tool. The actual affected packages overlap much more than the raw numbers imply.

### Tool Strengths and Weaknesses

| | Syft + Grype | Trivy |
|---|---|---|
| SBOM formats | CycloneDX, SPDX, syft-json | CycloneDX, SPDX, JSON |
| Secrets scanning | No | Yes |
| License scanning | In SBOM only | Built-in, dedicated scanner |
| Daemon-free scanning | Yes (tarball / OCI dir) | Needs Docker socket or rootless mode |
| Reusable artifact | SBOM is a standalone file, can re-scan against updated DBs | No reusable intermediate |
| False positives on LOW | Conservative | More inclusive (OS advisories) |

The main practical difference noticed during testing: Grype is faster when you already have an SBOM because it skips image pulling. Trivy is more convenient when you need secrets and license checks in a single command.

### Use Case Recommendations

Use **Syft + Grype** when you need to produce a portable SBOM as a compliance artifact (e.g. US EO 14028 requirements), share it with a customer, or feed it into a policy engine like OPA. The SBOM lets you re-scan against an updated vulnerability DB without re-pulling the image.

Use **Trivy** when you want a single tool covering vulnerabilities, secrets, and license checks in one CI step. Lower setup overhead and the official GitHub Action makes it easy to integrate.

### Integration Considerations

Both tools have official GitHub Actions and produce SARIF output that can be uploaded to the GitHub Security tab. For ephemeral CI runners, Trivy's vulnerability DB should be cached (mount `~/.cache/trivy` as a volume) to avoid downloading it on every run. Grype doesn't require a separate DB download when scanning an SBOM — the DB is fetched at Grype startup and cached similarly. Running both in the same pipeline (Syft SBOM → Grype + Trivy on the same image) gives the best coverage with acceptable overhead.
