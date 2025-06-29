#!/bin/bash

set -e

CRIT_COUNT=${CRIT_COUNT:-0}

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

{
echo "==============================================="
echo "          PatchHound - by BBlue530"
echo "==============================================="

echo "[~] Generating SBOM for: $TARGET"
syft "$TARGET" -o json > "sbom.json"
if [ ! -f "sbom.json" ]; then
  echo "[!] Error: sbom.json not found"
  exit 3
fi
echo "[+] SBOM created: sbom.json"

echo "[~] Uploading SBOM to scan service..."

response_and_status=$(curl --connect-timeout 60 --max-time 300 -s -w "\n%{http_code}" \
  -F "sbom=@sbom.json" \
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
  exit $curl_exit_code
fi

http_status=$(echo "$response_and_status" | tail -n1)
response_body=$(echo "$response_and_status" | head -n -1)

if [[ "$http_status" -ne 200 ]]; then
  echo "[!] Error: Server returned status $http_status"
  exit 5
fi

echo "[+] Upload to scan service finished"

RESPONSE="$response_body"
echo "$RESPONSE" | jq '.vulns_json' > vulns.json
echo "$RESPONSE" | jq '.vulns_cyclonedx_json' > vulns.cyclonedx.json

echo "[+] Vulnerability report received."

# Extract severity counts with defaults
CRIT_COUNT=$(jq '[.matches // [] | .[] | select(.vulnerability.severity == "Critical")] | length' "vulns.json")
HIGH_COUNT=$(jq '[.matches // [] | .[] | select(.vulnerability.severity == "High")] | length' "vulns.json")
MED_COUNT=$(jq '[.matches // [] | .[] | select(.vulnerability.severity == "Medium")] | length' "vulns.json")
LOW_COUNT=$(jq '[.matches // [] | .[] | select(.vulnerability.severity == "Low")] | length' "vulns.json")
UNKNOWN_COUNT=$(jq '[.matches // [] | .[] | select(.vulnerability.severity == "Unknown")] | length' "vulns.json")

echo "[i] Vulnerability assessment:"
echo "Critical: $CRIT_COUNT"
echo "High: $HIGH_COUNT"
echo "Medium: $MED_COUNT"
echo "Low: $LOW_COUNT"
echo "Unknown: $UNKNOWN_COUNT"

echo "[+] Full vulnerability report:"
echo "[~] Generating Summary"
echo "---------------------------------------------------------------------------"

jq -r '
  (.matches // [])[]
  | select(.vulnerability.severity == "Critical")
  | .vulnerability.id as $ID
  | (.vulnerability.description // "No description available") as $DESC
  | (.vulnerability.fix.versions[0] // "No fix available") as $FIX
  | ("https://cve.mitre.org/cgi-bin/cvename.cgi?name=" + $ID) as $LINK
  | .vulnerability.severity as $SEV
  | .artifact.name as $PKG_NAME
  | .artifact.version as $PKG_VER
  | "ID: \($ID)
Severity: \($SEV)
Package: \($PKG_NAME)@\($PKG_VER)
Cause: \($DESC)
Fix: \($FIX)
Link: \($LINK)
---------------------------------------------------------------------------"
' "vulns.json"
echo ""
} | tee "summary.md"

sleep 0.2

CRIT_COUNT=$(jq '[.matches // [] | .[] | select(.vulnerability.severity == "Critical")] | length' "vulns.json")
HIGH_COUNT=$(jq '[.matches // [] | .[] | select(.vulnerability.severity == "High")] | length' "vulns.json")
MED_COUNT=$(jq '[.matches // [] | .[] | select(.vulnerability.severity == "Medium")] | length' "vulns.json")
LOW_COUNT=$(jq '[.matches // [] | .[] | select(.vulnerability.severity == "Low")] | length' "vulns.json")
UNKNOWN_COUNT=$(jq '[.matches // [] | .[] | select(.vulnerability.severity == "Unknown")] | length' "vulns.json")
if [[ "$CRIT_COUNT" -gt 0 ]] && [[ -n "$DISCORD_WEBHOOK_URL" ]]; then
  echo "[!] Sending Discord alert with severity breakdown..." >&2
  sleep 0.2

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
  echo "[!] Sending Slack alert with severity breakdown..." >&2
  sleep 0.2

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


CRIT_COUNT=$(jq '[.matches // [] | .[] | select(.vulnerability.severity == "Critical")] | length' "vulns.json")
echo "$CRIT_COUNT" > crit_count.txt
if [ "$FAIL_ON_CRITICAL" = "true" ] && [ "$CRIT_COUNT" -gt 0 ]; then
  echo "[!] Failing due to $CRIT_COUNT critical vulnerabilities."
fi

syft convert sbom.json -o cyclonedx-json > sbom.cyclonedx.json

rm -f sbom.json vulns.json

echo "[+] Scan Finished"