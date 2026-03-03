#!/usr/bin/env bash
set -euo pipefail

echo "=== DAST Tools Summary ==="
echo ""

# ZAP
AUTH_JSON="labs/lab5/zap/zap-report-auth.json"
if [ -f "$AUTH_JSON" ]; then
  zap_total=$(jq '[.site[].alerts[]] | length' "$AUTH_JSON" 2>/dev/null || echo "0")
  zap_high=$(jq '[.site[].alerts[] | select(.riskdesc | startswith("High"))] | length' "$AUTH_JSON" 2>/dev/null || echo "0")
  zap_medium=$(jq '[.site[].alerts[] | select(.riskdesc | startswith("Medium"))] | length' "$AUTH_JSON" 2>/dev/null || echo "0")
  echo "ZAP (authenticated): $zap_total alerts | High: $zap_high | Medium: $zap_medium"
else
  echo "ZAP: report not found"
fi

# Nuclei
NUCLEI="labs/lab5/nuclei/nuclei-results.json"
if [ -f "$NUCLEI" ]; then
  nuclei_total=$(wc -l < "$NUCLEI" | tr -d ' ')
  nuclei_crit=$(grep -c '"severity":"critical"' "$NUCLEI" 2>/dev/null || echo "0")
  nuclei_high=$(grep -c '"severity":"high"' "$NUCLEI" 2>/dev/null || echo "0")
  echo "Nuclei: $nuclei_total findings | Critical: $nuclei_crit | High: $nuclei_high"
else
  echo "Nuclei: results not found"
fi

# Nikto
NIKTO="labs/lab5/nikto/nikto-results.txt"
if [ -f "$NIKTO" ]; then
  nikto_count=$(grep -c '^\+ ' "$NIKTO" 2>/dev/null || echo "0")
  echo "Nikto: $nikto_count findings"
else
  echo "Nikto: results not found"
fi

# SQLmap
sqlmap_csv=$(find labs/lab5/sqlmap -name "results-*.csv" 2>/dev/null | head -1)
if [ -f "${sqlmap_csv:-}" ]; then
  sqlmap_count=$(tail -n +2 "$sqlmap_csv" | grep -v '^$' | wc -l | tr -d ' ')
  echo "SQLmap: $sqlmap_count vulnerable endpoints confirmed"
else
  echo "SQLmap: results not found"
fi
