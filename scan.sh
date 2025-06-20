#!/bin/bash

set -e

command -v syft >/dev/null 2>&1 || { echo >&2 "Syft not installed. Exiting."; exit 1; }
command -v grype >/dev/null 2>&1 || { echo >&2 "Grype not installed. Exiting."; exit 1; }
command -v chainloop >/dev/null 2>&1 || { echo >&2 "Chainloop not installed. Exiting."; exit 1; }

IMAGE="$1"
THRESHOLD="${2:-CRITICAL}"

echo "[+] Generating SBOM for $IMAGE"
syft "$IMAGE" -o json > sbom.json

echo "[+] Scanning for vulnerabilities"
grype sbom:sbom.json -o json > vulns.json

# Count CVEs by severity
HIGH_COUNT=$(jq '[.matches[] | select(.vulnerability.severity == "High")] | length' vulns.json)
CRIT_COUNT=$(jq '[.matches[] | select(.vulnerability.severity == "Critical")] | length' vulns.json)

echo "High: $HIGH_COUNT"
echo "Critical: $CRIT_COUNT"

# Discord alert on criticals
if [ "$CRIT_COUNT" -gt 0 ]; then
  echo "[!] Sending Discord alert for critical CVEs..."
  MESSAGE=$(jq -n --arg img "$IMAGE" --arg count "$CRIT_COUNT" \
    '{
      "embeds": [{
        "title": "🚨 Critical CVEs Detected",
        "description": "**Image:** \($img)\n**Critical Count:** \($count)",
        "color": 16711680
      }]
    }')

  curl -X POST -H "Content-Type: application/json" \
    -d "$MESSAGE" \
    "$DISCORD_WEBHOOK_URL"
fi

# Threshold enforcement
if [ "$THRESHOLD" == "CRITICAL" ] && [ "$CRIT_COUNT" -gt 0 ]; then
  echo "[!] Critical vulnerabilities found. Failing build."
  exit 1
fi

if [ "$THRESHOLD" == "HIGH" ] && [ "$HIGH_COUNT" -gt 0 ]; then
  echo "[!] High vulnerabilities found. Failing build."
  exit 1
fi

echo "[+] Signing artifact with Chainloop"
chainloop attestation sign --attestation sbom.json --artifact "$IMAGE"

echo "[✓] Done!"