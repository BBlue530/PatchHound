set -e

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

# Slack alert on criticals
if [ "$CRIT_COUNT" -gt 0 ]; then
  echo "[!] Sending Slack alert for criticals..."
  MESSAGE=$(jq -n --arg img "$IMAGE" --arg count "$CRIT_COUNT" \
    '{"text": "🚨 *Critical CVEs detected!*\nImage: \($img)\nCount: \($count)"}')

  curl -X POST -H 'Content-type: application/json' \
    --data "$MESSAGE" \
    "$SLACK_WEBHOOK_URL"
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