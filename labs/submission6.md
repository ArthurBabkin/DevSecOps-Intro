# Lab 6 — IaC Security: Scanning & Policy Enforcement

**Target:** `labs/lab6/vulnerable-iac/` (Terraform · Pulumi · Ansible)

---

## Task 1 — Terraform & Pulumi Security Scanning

### Commands

```bash
mkdir -p labs/lab6/analysis

# tfsec — Terraform
docker run --rm -v "$(pwd)/labs/lab6/vulnerable-iac/terraform":/src \
  aquasec/tfsec:latest /src --format json --out /src/tfsec-out.json
cp labs/lab6/vulnerable-iac/terraform/tfsec-out.json labs/lab6/analysis/tfsec-results.json
docker run --rm -v "$(pwd)/labs/lab6/vulnerable-iac/terraform":/src \
  aquasec/tfsec:latest /src --format text --out /src/tfsec-report.txt
cp labs/lab6/vulnerable-iac/terraform/tfsec-report.txt labs/lab6/analysis/

# Checkov — Terraform
docker run --rm \
  -v "$(pwd)/labs/lab6/vulnerable-iac/terraform":/tf \
  -v "$(pwd)/labs/lab6/analysis":/out \
  bridgecrew/checkov:latest -d /tf --framework terraform -o json 2>/dev/null \
  | tee labs/lab6/analysis/checkov-terraform-results.json > /dev/null
docker run --rm \
  -v "$(pwd)/labs/lab6/vulnerable-iac/terraform":/tf \
  -v "$(pwd)/labs/lab6/analysis":/out \
  bridgecrew/checkov:latest -d /tf --framework terraform --compact \
  -o cli --output-file-path /out 2>/dev/null
mv labs/lab6/analysis/results_cli.txt labs/lab6/analysis/checkov-terraform-report.txt

# Terrascan — Terraform
docker run --rm -v "$(pwd)/labs/lab6/vulnerable-iac/terraform":/iac \
  tenable/terrascan:latest scan -i terraform -d /iac -o json 2>/dev/null \
  > labs/lab6/analysis/terrascan-results.json

# Count results
tfsec_count=$(jq '.results | length' labs/lab6/analysis/tfsec-results.json)
checkov_count=$(jq '.summary.failed' labs/lab6/analysis/checkov-terraform-results.json)
terrascan_count=$(jq '.results.scan_summary.violated_policies' labs/lab6/analysis/terrascan-results.json)
echo "tfsec: $tfsec_count | Checkov: $checkov_count | Terrascan: $terrascan_count" \
  >> labs/lab6/analysis/terraform-comparison.txt
```

Output: `labs/lab6/analysis/terraform-comparison.txt`, `tfsec-results.json`, `checkov-terraform-results.json`, `terrascan-results.json`

### Terraform Tool Comparison

| Tool | Total | CRITICAL | HIGH | MEDIUM | LOW |
|------|------:|--------:|-----:|------:|----:|
| tfsec | 53 | 9 | 25 | 11 | 8 |
| Checkov | 78 | — | — | — | — |
| Terrascan | 22 | — | 14 | 8 | 0 |

Checkov found the most (78) because it checks compliance posture too — missing S3 versioning, no cross-region replication, missing lifecycle policies. Those aren't exploitable vulnerabilities but they count. tfsec found the most high-severity actionable issues (34 CRITICAL/HIGH) by staying focused on exposures: all the `0.0.0.0/0` security group rules came back CRITICAL. Terrascan found the fewest (22) but with the lowest noise — its OPA-based rules are conservative and map directly to CIS/NIST benchmarks.

**Tool strengths:**  
tfsec is the sharpest tool for network exposure and misconfigurations — it caught every open security group ingress/egress rule as CRITICAL and flagged the publicly accessible RDS instance immediately. Checkov's strength is breadth — 1000+ built-in policies covering IAM, S3, RDS, encryption, logging, and governance. Terrascan is best when you need findings mapped to a specific compliance framework rather than a raw finding list.

### Pulumi — KICS

```bash
docker run --rm -v "$(pwd)/labs/lab6/vulnerable-iac/pulumi":/src \
  checkmarx/kics:latest scan -p /src -o /src/kics-report --report-formats json,html
cp labs/lab6/vulnerable-iac/pulumi/kics-report/results.json labs/lab6/analysis/kics-pulumi-results.json
cp labs/lab6/vulnerable-iac/pulumi/kics-report/results.html labs/lab6/analysis/kics-pulumi-report.html

docker run --rm -v "$(pwd)/labs/lab6/vulnerable-iac/pulumi":/src \
  checkmarx/kics:latest scan -p /src --minimal-ui \
  > labs/lab6/analysis/kics-pulumi-report.txt 2>&1 || true

high_severity=$(jq '.severity_counters.HIGH // 0' labs/lab6/analysis/kics-pulumi-results.json)
medium_severity=$(jq '.severity_counters.MEDIUM // 0' labs/lab6/analysis/kics-pulumi-results.json)
total_findings=$(jq '.total_counter // 0' labs/lab6/analysis/kics-pulumi-results.json)
```

Output: `labs/lab6/analysis/pulumi-analysis.txt`, `kics-pulumi-results.json`

### Pulumi Security Analysis

KICS auto-detected the Pulumi YAML format and found **6 findings**:

| Severity | Finding |
|----------|---------|
| CRITICAL | RDS DB Instance Publicly Accessible |
| HIGH | DynamoDB Table Not Encrypted |
| HIGH | Generic Password in config |
| MEDIUM | EC2 Instance Monitoring Disabled |
| INFO | DynamoDB Point-In-Time Recovery Disabled |
| INFO | EC2 Not EBS Optimized |

The low count (6 vs 53 for Terraform) doesn't mean the Pulumi code is cleaner — it reflects that KICS's Pulumi query catalog is smaller and less mature than the dedicated Terraform tools. The issues it did find are the same category as the Terraform problems: public database exposure, missing encryption, hardcoded credentials. KICS correctly auto-detected the `Pulumi-vulnerable.yaml` manifest without any configuration.

**Terraform vs Pulumi:** Both codebases have the same types of misconfigurations — open access, no encryption, plaintext secrets. The difference is purely tooling maturity. tfsec and Checkov have years of Terraform-specific rules; KICS's Pulumi support is newer and covers fewer checks. From a risk perspective both are equally dangerous.

**KICS Pulumi support:** Works well for the fundamentals — it catches public exposure and unencrypted resources reliably. The query catalog covers AWS, Azure, GCP, and Kubernetes resources in Pulumi YAML. What it misses is the Python-based Pulumi code (`__main__.py`) — KICS only scans the YAML manifest, so any misconfigurations in the Python layer are invisible to it.

### Critical Findings (top 5)

| # | Finding | Tool | Location | Severity |
|---|---------|------|----------|----------|
| 1 | Security group allows ingress from `0.0.0.0/0` on all ports | tfsec | `security_groups.tf:15` | CRITICAL |
| 2 | RDS instance publicly accessible | tfsec / KICS | `database.tf:17` / Pulumi YAML | CRITICAL |
| 3 | Hardcoded AWS credentials | tfsec / Checkov | `variables.tf` | CRITICAL |
| 4 | S3 bucket with public READ ACL and no encryption | Checkov | `main.tf:13` | HIGH |
| 5 | IAM policy with wildcard `*` permissions | Checkov | `iam.tf:5` | HIGH |

---

## Task 2 — Ansible Security Scanning with KICS

### Commands

```bash
docker run --rm -v "$(pwd)/labs/lab6/vulnerable-iac/ansible":/src \
  checkmarx/kics:latest scan -p /src -o /src/kics-report --report-formats json,html
cp labs/lab6/vulnerable-iac/ansible/kics-report/results.json labs/lab6/analysis/kics-ansible-results.json
cp labs/lab6/vulnerable-iac/ansible/kics-report/results.html labs/lab6/analysis/kics-ansible-report.html

docker run --rm -v "$(pwd)/labs/lab6/vulnerable-iac/ansible":/src \
  checkmarx/kics:latest scan -p /src --minimal-ui \
  > labs/lab6/analysis/kics-ansible-report.txt 2>&1 || true

high_severity=$(jq '.severity_counters.HIGH // 0' labs/lab6/analysis/kics-ansible-results.json)
total_findings=$(jq '.total_counter // 0' labs/lab6/analysis/kics-ansible-results.json)
```

Output: `labs/lab6/analysis/ansible-analysis.txt`, `kics-ansible-results.json`

### Ansible Security Issues

KICS found **10 findings**: 9 HIGH, 1 LOW.

| Severity | Finding | File |
|----------|---------|------|
| HIGH | Generic Password in plaintext | `inventory.ini`, `deploy.yml` |
| HIGH | Generic Secret in plaintext | `deploy.yml` |
| HIGH | Password embedded in URL | `configure.yml` |
| LOW | Unpinned package version | `deploy.yml` |

### Best Practice Violations

**1. Plaintext credentials in inventory (`inventory.ini`)**  
`ansible_ssh_pass`, `ansible_become_password`, `db_admin_password`, and `api_secret_key` are all stored in cleartext in the inventory file. Anyone with read access to the repo — including CI/CD logs — gets these credentials. Impact: full server access and database compromise.  
Fix: use Ansible Vault — `ansible-vault encrypt_string 'value' --name 'db_admin_password'` — or pull secrets from AWS SSM/HashiCorp Vault at runtime.

**2. Password embedded in connection URL (`configure.yml`)**  
Database URLs are built with credentials inline (e.g. `postgresql://admin:pass@host/db`). These strings show up in process listings (`ps aux`), application logs, and error traces.  
Fix: build connection strings from separate variables that are either vault-encrypted or injected as environment variables; never concatenate credentials into URLs in playbook tasks.

**3. Unpinned package versions (`deploy.yml`)**  
Packages are installed with `state: latest` or no version pinned. A silent upstream update can break deployments or introduce a vulnerable package version without any change to the playbook.  
Fix: pin versions explicitly — `name: nginx=1.24.0` — and upgrade via controlled change management.

### KICS Ansible Query Coverage

KICS covers secrets management, SSH configuration, file permissions, command execution (`shell` vs proper modules), and `no_log` enforcement. In practice it was strongest at detecting hardcoded credential patterns — all 9 HIGH findings come from plaintext secrets. It didn't flag the `shell` module usage or missing `no_log: true` on sensitive tasks, which means those queries either require a newer KICS version or need to be supplemented with `ansible-lint`.

---

## Task 3 — Comparative Tool Analysis

### Summary statistics

```bash
tfsec_count=$(jq '.results | length' labs/lab6/analysis/tfsec-results.json)
checkov_tf_count=$(jq '.summary.failed' labs/lab6/analysis/checkov-terraform-results.json)
terrascan_count=$(jq '.results.scan_summary.violated_policies' labs/lab6/analysis/terrascan-results.json)
kics_pulumi_count=$(jq '.total_counter // 0' labs/lab6/analysis/kics-pulumi-results.json)
kics_ansible_count=$(jq '.total_counter // 0' labs/lab6/analysis/kics-ansible-results.json)
```

Output: `labs/lab6/analysis/tool-comparison.txt`

### Tool Comparison Matrix

| Criterion | tfsec | Checkov | Terrascan | KICS |
|-----------|-------|---------|-----------|------|
| Total findings (Terraform) | 53 | 78 | 22 | — |
| Total findings (Pulumi + Ansible) | — | — | — | 16 |
| Scan speed | Fast | Medium | Medium | Medium |
| False positives | Low | Medium | Low | Low |
| Report quality | Good | Excellent | Good | Excellent |
| Ease of use | Easy | Easy | Medium | Medium |
| Platform support | Terraform only | Terraform, CF, K8s, Docker | Terraform, K8s | Terraform, Pulumi, Ansible, K8s, Docker, CF |
| Output formats | JSON, text, SARIF, JUnit | JSON, CLI, SARIF, JUnit | JSON, YAML, SARIF | JSON, HTML, SARIF, JUnit |
| CI/CD integration | Easy | Easy | Medium | Medium |

### Category Analysis

| Security Category | tfsec | Checkov | Terrascan | KICS (Pulumi) | KICS (Ansible) | Best tool |
|---|---|---|---|---|---|---|
| Encryption | ✅ HIGH | ✅ many | ✅ HIGH | ✅ CRITICAL | N/A | Checkov |
| Network security | ✅ CRITICAL | ✅ | ✅ | ✅ | N/A | tfsec |
| Secrets management | ✅ HIGH | ✅ | ❌ | ✅ HIGH | ✅ 9 HIGH | KICS |
| IAM / permissions | ✅ HIGH | ✅ extensive | ✅ HIGH | N/A | N/A | Checkov |
| Compliance / best practices | ❌ limited | ✅ | ✅ CIS/NIST | ✅ INFO | ✅ LOW | Checkov + Terrascan |

### Top 5 Critical Findings with Remediation

**1. Security group allows all ingress from `0.0.0.0/0` (`security_groups.tf:15`)**  
Any host on the internet can connect on any port. Detected by tfsec as CRITICAL.
```hcl
ingress {
  from_port   = 443
  to_port     = 443
  protocol    = "tcp"
  cidr_blocks = ["10.0.0.0/8"]
}
```

**2. RDS publicly accessible (`database.tf:17`, Pulumi YAML)**  
`publicly_accessible = true` puts the database endpoint on the internet. Detected by both tfsec and KICS as CRITICAL.
```hcl
publicly_accessible  = false
db_subnet_group_name = aws_db_subnet_group.private.name
```

**3. Hardcoded AWS credentials (`variables.tf`)**  
Secrets in VCS are compromised at the moment of the first push. Remove them entirely — reference via `data "aws_ssm_parameter"` or `TF_VAR_*` environment variables injected by the CI system.

**4. S3 bucket public READ ACL with no encryption (`main.tf:13`)**  
`acl = "public-read"` and no `server_side_encryption_configuration`. Detected by Checkov.
```hcl
resource "aws_s3_bucket_acl" "example" { acl = "private" }
resource "aws_s3_bucket_server_side_encryption_configuration" "example" {
  rule { apply_server_side_encryption_by_default { sse_algorithm = "AES256" } }
}
```

**5. Hardcoded credentials in Ansible inventory (`inventory.ini`)**  
Plaintext `ansible_ssh_pass` and `db_admin_password` in the inventory file. Detected by KICS as HIGH.
```ini
[webservers]
host1 ansible_user=deploy ansible_ssh_private_key_file=~/.ssh/deploy_key
```
Secrets go in an Ansible Vault-encrypted `group_vars/all/vault.yml`, referenced as `{{ vault_db_password }}`.

### Tool Selection Guide

**tfsec** — best default choice for Terraform-only repos. Fast enough for pre-commit hooks, CRITICAL/HIGH findings are almost always real issues with minimal noise.  
**Checkov** — use when coverage matters more than noise ratio: compliance checks, governance policies, multi-framework repos (K8s, Docker, Terraform together).  
**Terrascan** — use when you need to report against a specific compliance framework (CIS Benchmark, NIST 800-53, HIPAA). The OPA backend also lets you add custom policies.  
**KICS** — the only reasonable choice for Pulumi and Ansible. If your IaC stack is mixed (Terraform + Pulumi + Ansible), KICS gives you one tool instead of three.

### CI/CD Integration Strategy

A practical multi-stage setup:

1. **Pre-commit** — tfsec (seconds to run, blocks the most dangerous misconfigurations before they reach the repo)
2. **PR check** — Checkov (full policy library, fails the PR on CRITICAL/HIGH, posts SARIF results to GitHub Security tab)
3. **Nightly/scheduled** — Terrascan (compliance mapping, audit evidence) + KICS (Pulumi and Ansible coverage)
4. **Deployment gate** — any CRITICAL from any tool blocks `terraform apply`; HIGH requires a manual approval step

The overlap between tools is intentional — tfsec catches network exposure that Checkov sometimes rates medium; Checkov catches governance gaps that tfsec doesn't check at all. The small overhead of running two tools on the critical path is worth it compared to a missed CRITICAL.

**Justification:** tfsec + Checkov in the PR pipeline gives the best balance of speed and coverage for Terraform. KICS is added as a separate step rather than replacing either, because its Terraform coverage is less mature than the dedicated tools. For Ansible there's no better free option than KICS, though it should be complemented by `ansible-lint` for rule violations that KICS misses (`no_log`, `shell` module overuse).

### Lessons Learned

Raw finding counts are misleading when comparing these tools. Checkov's 78 findings look more thorough than tfsec's 53, but 20+ of those are compliance/governance checks (cross-region replication, lifecycle policies, event notifications) rather than security vulnerabilities. A security engineer prioritizing work should start with tfsec's 9 CRITICAL findings, not Checkov's total.

The Pulumi finding count from KICS (6) is similarly misleading in the other direction — it's low because the query catalog is small, not because the code is safe. Running KICS on Pulumi and getting a short list should not be read as a green light.

KICS's Ansible secrets detection was solid, but it missed `shell` module usage and tasks that should have `no_log: true`. Teams relying only on KICS for Ansible scanning have gaps that `ansible-lint` would catch.
