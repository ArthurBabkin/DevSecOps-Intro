#!/usr/bin/env bash
set -euo pipefail

here_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
out_dir="$here_dir"

require_env() {
  local name="$1"
  if [[ -z "${!name:-}" ]]; then
    echo "ERROR: env var $name is required" >&2
    exit 1
  fi
}

require_env DD_API
require_env DD_TOKEN

DD_PRODUCT_TYPE="${DD_PRODUCT_TYPE:-Engineering}"
DD_PRODUCT="${DD_PRODUCT:-Juice Shop}"
DD_ENGAGEMENT="${DD_ENGAGEMENT:-Labs Security Testing}"

echo "DD_API=$DD_API"
echo "DD_PRODUCT_TYPE=$DD_PRODUCT_TYPE DD_PRODUCT=$DD_PRODUCT DD_ENGAGEMENT=$DD_ENGAGEMENT"

have_jq=true
command -v jq >/dev/null 2>&1 || have_jq=false
$have_jq || echo "WARN: no jq, using default scan_type strings" >&2

SCAN_ZAP="${SCAN_ZAP:-}"
SCAN_SEMGREP="${SCAN_SEMGREP:-}"
SCAN_TRIVY="${SCAN_TRIVY:-}"
SCAN_NUCLEI="${SCAN_NUCLEI:-}"

if $have_jq; then
  types=()
  while IFS= read -r line; do
    [[ -n "$line" ]] && types+=("$line")
  done < <(curl -sS -H "Authorization: Token $DD_TOKEN" "$DD_API/test_types/?limit=2000" | jq -r '.results[].name')
  pick() {
    local pat="$1" fb="$2" v=""
    for t in "${types[@]}"; do
      if [[ "$t" =~ $pat ]]; then v="$t"; break; fi
    done
    echo "${v:-$fb}"
  }
  SCAN_ZAP="${SCAN_ZAP:-$(pick '^ZAP' 'ZAP Scan')}"
  SCAN_SEMGREP="${SCAN_SEMGREP:-$(pick '^Semgrep' 'Semgrep JSON Report')}"
  SCAN_TRIVY="${SCAN_TRIVY:-$(pick '^Trivy' 'Trivy Scan')}"
  SCAN_NUCLEI="${SCAN_NUCLEI:-$(pick '^Nuclei' 'Nuclei Scan')}"
  if [[ -z "${SCAN_GRYPE:-}" ]]; then
    SCAN_GRYPE=$(printf '%s\n' "${types[@]}" | grep -i '^Anchore Grype' | head -n1)
    [[ -n "$SCAN_GRYPE" ]] || SCAN_GRYPE=$(printf '%s\n' "${types[@]}" | grep -i 'Grype' | head -n1)
  fi
else
  SCAN_ZAP="${SCAN_ZAP:-ZAP Scan}"
  SCAN_SEMGREP="${SCAN_SEMGREP:-Semgrep JSON Report}"
  SCAN_TRIVY="${SCAN_TRIVY:-Trivy Scan}"
  SCAN_NUCLEI="${SCAN_NUCLEI:-Nuclei Scan}"
fi
SCAN_GRYPE="${SCAN_GRYPE:-Anchore Grype}"

echo "scan types: zap=$SCAN_ZAP semgrep=$SCAN_SEMGREP trivy=$SCAN_TRIVY nuclei=$SCAN_NUCLEI grype=$SCAN_GRYPE"

import_scan() {
  local scan_type="$1" file="$2"
  if [[ ! -f "$file" ]]; then
    echo "SKIP $scan_type ($file missing)"
    return 0
  fi
  local base stem out
  base="$(basename "$file")"
  stem="${base//[^A-Za-z0-9_.-]/_}"
  stem="${stem%.*}"
  out="$out_dir/import-${stem}.json"
  echo "POST $scan_type <= $file"
  curl -sS -X POST "$DD_API/import-scan/" \
    -H "Authorization: Token $DD_TOKEN" \
    -F "scan_type=$scan_type" \
    -F "file=@$file" \
    -F "product_type_name=$DD_PRODUCT_TYPE" \
    -F "product_name=$DD_PRODUCT" \
    -F "engagement_name=$DD_ENGAGEMENT" \
    -F "auto_create_context=true" \
    -F "minimum_severity=Info" \
    -F "close_old_findings=false" \
    -F "push_to_jira=false" \
    | tee "$out"
}

zap_file="labs/lab10/imports/zap-report-noauth.xml"
[[ -f "$zap_file" ]] || zap_file="labs/lab5/zap/zap-report-noauth.json"

import_scan "$SCAN_ZAP"     "$zap_file"
import_scan "$SCAN_SEMGREP" "labs/lab5/semgrep/semgrep-results.json"
import_scan "$SCAN_TRIVY"   "labs/lab4/trivy/trivy-vuln-detailed.json"
import_scan "$SCAN_NUCLEI"  "labs/lab5/nuclei/nuclei-results.json"
import_scan "$SCAN_GRYPE"   "labs/lab4/syft/grype-vuln-results.json"

echo "done -> $out_dir"
