#!/bin/bash

set -e

CONFIG_FILE="${1:-scan.config}"
if [ -f "$CONFIG_FILE" ]; then
  source "$CONFIG_FILE"
else
  echo "[-] Config file '$CONFIG_FILE' not found!"
  exit 1
fi

# Ensure secrets are set
if [[ -z "$DISCORD_WEBHOOK_URL" && -z "$SLACK_WEBHOOK_URL" ]]; then
  echo "[!] SLACK_WEBHOOK_URL and DISCORD_WEBHOOK_URL is not set, no alerts will be sent."
fi

if [[ -z "$SBOM_SCAN_API_URL" ]]; then
  echo "[!] SBOM_SCAN_API_URL is not set! Workflow will not work and will now exit."
  exit 2
fi

if [[ -z "$LICENSE_SECRET" ]]; then
  echo "[!] LICENSE_SECRET is not set! Workflow will not work and will now exit."
  exit 2
fi

echo "[~] Generating SBOM for: $TARGET"
syft "$TARGET" -o json > "$SBOM_OUTPUT"
echo "[+] SBOM created: $SBOM_OUTPUT"

if [ ! -f "$SBOM_OUTPUT" ]; then
  echo "[!] Error: sbom.json not found"
  exit 3
fi

echo "[~] Uploading SBOM to scan service..."

response_and_status=$(curl --connect-timeout 60 --max-time 300 -s -w "\n%{http_code}" \
  -F "sbom=@$SBOM_OUTPUT" \
  -F "license=$LICENSE_SECRET" \
  "$SBOM_SCAN_API_URL")

curl_exit_code=$?

http_status=$(echo "$response_and_status" | tail -n1)
response_body=$(echo "$response_and_status" | head -n -1)

if [[ "$http_status" -ne 200 ]]; then
  echo "[!] Error: Status Code: $http_status"
  echo "$response_body"
  exit 1
fi

if [ $curl_exit_code -ne 0 ]; then
  echo "[!] Error: curl failed with exit code $curl_exit_code"
  rm -f "$SBOM_OUTPUT"
  exit $curl_exit_code
fi

http_status=$(echo "$response_and_status" | tail -n1)
response_body=$(echo "$response_and_status" | head -n -1)

echo "[+] Upload to scan service finished"

if [[ "$http_status" -ne 200 ]]; then
  echo "[!] Error: Server returned status $http_status"
  rm -f "$SBOM_OUTPUT"
  exit 5
fi

if ! echo "$response_body" | jq -e '.severity_counts' > /dev/null; then
  echo "[!] Error: Response JSON missing severity_counts key or invalid JSON"
  rm -f "$SBOM_OUTPUT"
  exit 5
fi

RESPONSE="$response_body"
echo "$RESPONSE" > "$VULN_OUTPUT"

echo "[+] Vulnerability report received."

if ! echo "$RESPONSE" | jq -e '.severity_counts' > /dev/null; then
  echo "[!] ERROR: Response JSON missing severity_counts key or invalid JSON"
  exit 5
fi

# Extract severity counts with defaults
CRIT_COUNT=$(echo "$RESPONSE" | jq -r '.severity_counts.Critical // 0')
HIGH_COUNT=$(echo "$RESPONSE" | jq -r '.severity_counts.High // 0')
MED_COUNT=$(echo "$RESPONSE" | jq -r '.severity_counts.Medium // 0')
LOW_COUNT=$(echo "$RESPONSE" | jq -r '.severity_counts.Low // 0')
UNKNOWN_COUNT=$(echo "$RESPONSE" | jq -r '.severity_counts.Unknown // 0')

echo "[i] Vulnerability assessment:"
echo "Critical: $CRIT_COUNT"
echo "High: $HIGH_COUNT"
echo "Medium: $MED_COUNT"
echo "Low: $LOW_COUNT"
echo "Unknown: $UNKNOWN_COUNT"

echo "[+] Full vulnerability report:"
jq '.' "$VULN_OUTPUT"

if [[ "$CRIT_COUNT" -gt 0 ]] && [[ -n "$DISCORD_WEBHOOK_URL" ]]; then
  echo "[!] Sending Discord alert with severity breakdown..."

  MESSAGE=$(jq -n \
  --arg img "$IMAGE" \
  --arg crit "$CRIT_COUNT" \
  --arg high "$HIGH_COUNT" \
  --arg med "$MED_COUNT" \
  --arg low "$LOW_COUNT" \
  --arg unknown "$UNKNOWN_COUNT" \
    '{
      "embeds": [{
        "title": "🚨 Vulnerability Severity Report",
        "description": "**Image:** \($img)\n\n**Critical:** \($crit)\n**High:** \($high)\n**Medium:** \($med)\n**Low:** \($low)\n**Unknown:** \($unknown)",
        "color": 16711680
      }]
    }'
  )

  curl -X POST -H "Content-Type: application/json" \
    -d "$MESSAGE" \
    "$DISCORD_WEBHOOK_URL"

  CURL_EXIT=$?
  if [ $CURL_EXIT -ne 0 ]; then
    echo "[!] Curl to Discord failed with exit code $CURL_EXIT"
    exit $CURL_EXIT
  fi
fi

if [[ "$CRIT_COUNT" -gt 0 ]] && [[ -n "$SLACK_WEBHOOK_URL" ]]; then
  echo "[!] Sending Slack alert with severity breakdown..."

  MESSAGE=$(jq -n \
    --arg img "$IMAGE" \
    --arg crit "$CRIT_COUNT" \
    --arg high "$HIGH_COUNT" \
    --arg med "$MED_COUNT" \
    --arg low "$LOW_COUNT" \
    --arg unknown "$UNKNOWN_COUNT" \
    '{
      text: ":rotating_light: *Vulnerability Severity Report*",
      attachments: [
        {
          color: "#FF0000",
          fields: [
            { title: "Image", value: $img, short: false },
            { title: "Critical", value: $crit, short: true },
            { title: "High", value: $high, short: true },
            { title: "Medium", value: $med, short: true },
            { title: "Low", value: $low, short: true },
            { title: "Unknown", value: $unknown, short: true }
          ]
        }
      ]
    }'
  )

  curl -X POST -H "Content-Type: application/json" \
    -d "$MESSAGE" \
    "$SLACK_WEBHOOK_URL"

  CURL_EXIT=$?
  if [ $CURL_EXIT -ne 0 ]; then
    echo "[!] Curl to Slack failed with exit code $CURL_EXIT"
    exit $CURL_EXIT
  fi
fi

rm -f "$SBOM_OUTPUT"

echo "[+] Scan Finished"