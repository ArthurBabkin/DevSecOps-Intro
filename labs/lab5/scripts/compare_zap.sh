#!/usr/bin/env bash
set -euo pipefail

NOAUTH="labs/lab5/zap/zap-report-noauth.json"
AUTH="labs/lab5/zap/zap-report-auth.json"

echo "=== ZAP Authenticated vs Unauthenticated Comparison ==="
echo ""

if [ -f "$NOAUTH" ]; then
  noauth_alerts=$(jq '[.site[].alerts[]] | length' "$NOAUTH" 2>/dev/null || echo "0")
  noauth_high=$(jq '[.site[].alerts[] | select(.riskdesc | startswith("High"))] | length' "$NOAUTH" 2>/dev/null || echo "0")
  noauth_medium=$(jq '[.site[].alerts[] | select(.riskdesc | startswith("Medium"))] | length' "$NOAUTH" 2>/dev/null || echo "0")
  echo "Unauthenticated scan:"
  echo "  Total alerts : $noauth_alerts"
  echo "  High         : $noauth_high"
  echo "  Medium       : $noauth_medium"
else
  echo "Unauthenticated report not found: $NOAUTH"
fi

echo ""

if [ -f "$AUTH" ]; then
  auth_alerts=$(jq '[.site[].alerts[]] | length' "$AUTH" 2>/dev/null || echo "0")
  auth_high=$(jq '[.site[].alerts[] | select(.riskdesc | startswith("High"))] | length' "$AUTH" 2>/dev/null || echo "0")
  auth_medium=$(jq '[.site[].alerts[] | select(.riskdesc | startswith("Medium"))] | length' "$AUTH" 2>/dev/null || echo "0")
  echo "Authenticated scan:"
  echo "  Total alerts : $auth_alerts"
  echo "  High         : $auth_high"
  echo "  Medium       : $auth_medium"
  echo ""
  echo "Authenticated endpoints discovered (sample):"
  jq -r '.site[].alerts[].instances[].uri' "$AUTH" 2>/dev/null \
    | grep -i "admin\|account\|profile\|basket\|order\|payment" \
    | sort -u | head -10
else
  echo "Authenticated report not found: $AUTH"
fi
