#!/bin/bash

set -e

IMAGE="$1"

# Ensure environment variables are set via secrets or environment
if [[ -z "$IMAGE" ]]; then
  echo "Usage: $0 <image>"
  exit 1
fi

if [[ -z "$SBOM_SCAN_API_URL" ]]; then
  echo "Error: SBOM_SCAN_API_URL environment variable is not set."
  exit 1
fi

if [[ -z "$DISCORD_WEBHOOK_URL" ]]; then
  echo "Warning: DISCORD_WEBHOOK_URL is not set, no alerts will be sent."
fi

echo "[+] Generating SBOM for $IMAGE"
syft "$IMAGE" -o json > sbom.json

echo "[+] Uploading SBOM to scan service..."
RESPONSE=$(curl --connect-timeout 5 --max-time 30 -s -w "%{http_code}" \
  -F "sbom=@sbom.json" \
  -F "license=$LICENSE_SECRET" \
  "$SBOM_SCAN_API_URL")

HTTP_CODE="${RESPONSE: -3}"
BODY="${RESPONSE:0:-3}"

echo "Curl HTTP status code: $HTTP_CODE"
echo "Response body: $BODY"

if [[ "$HTTP_CODE" -ne 200 ]]; then
  echo "Error scanning SBOM: HTTP $HTTP_CODE"
  rm -f sbom.json
  exit 1
fi

echo "[+] Vulnerability report received."

# Extract severity counts with defaults
CRIT_COUNT=$(echo "$RESPONSE" | jq '.severity_counts.Critical // 0')
HIGH_COUNT=$(echo "$RESPONSE" | jq '.severity_counts.High // 0')
MED_COUNT=$(echo "$RESPONSE" | jq '.severity_counts.Medium // 0')
LOW_COUNT=$(echo "$RESPONSE" | jq '.severity_counts.Low // 0')
UNKNOWN_COUNT=$(echo "$RESPONSE" | jq '.severity_counts.Unknown // 0')

echo "Critical: $CRIT_COUNT"
echo "High: $HIGH_COUNT"
echo "Medium: $MED_COUNT"
echo "Low: $LOW_COUNT"
echo "Unknown: $UNKNOWN_COUNT"

# Discord alert if critical vulnerabilities found
if [[ "$CRIT_COUNT" -gt 0 ]] && [[ -n "$DISCORD_WEBHOOK_URL" ]]; then
  echo "[!] Sending Discord alert with severity breakdown..."
  MESSAGE=$(jq -n \
    --arg img "$IMAGE" \
    --argjson crit "$CRIT_COUNT" \
    --argjson high "$HIGH_COUNT" \
    --argjson med "$MED_COUNT" \
    --argjson low "$LOW_COUNT" \
    --argjson unknown "$UNKNOWN_COUNT" \
    '{
      "embeds": [{
        "title": "🚨 Vulnerability Severity Report",
        "description": "**Image:** \($img)\n\n" +
                       "**Critical:** \($crit)\n" +
                       "**High:** \($high)\n" +
                       "**Medium:** \($med)\n" +
                       "**Low:** \($low)\n" +
                       "**Unknown:** \($unknown)",
        "color": 16711680
      }]
    }')

  curl -X POST -H "Content-Type: application/json" \
    -d "$MESSAGE" \
    "$DISCORD_WEBHOOK_URL"
fi

rm -f sbom.json

echo "[✓] Done!"