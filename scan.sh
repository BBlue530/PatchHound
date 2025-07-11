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
  echo "[!] SLACK_WEBHOOK_URL and DISCORD_WEBHOOK_URL are not set, no alerts will be sent."
else
  # This will prio discord for the alert inside the backend
  if [[ -n "$DISCORD_WEBHOOK_URL" ]]; then
    ALERT_SYSTEM="discord"
    ALERT_SYSTEM_WEBHOOK="$DISCORD_WEBHOOK_URL"
  elif [[ -n "$SLACK_WEBHOOK_URL" ]]; then
    ALERT_SYSTEM="slack"
    ALERT_SYSTEM_WEBHOOK="$SLACK_WEBHOOK_URL"
  fi
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
syft "$TARGET" -o cyclonedx-json > sbom.cyclonedx.json
if [ ! -f "sbom.cyclonedx.json" ]; then
  echo "[!] Error: sbom.json not found"
  exit 3
fi
echo "[+] SBOM created: sbom.cyclonedx.json"

echo "[~] Uploading SBOM to scan service..."

response_and_status=$(curl --connect-timeout 60 --max-time 300 -s -w "\n%{http_code}" \
  -F "sbom=@sbom.cyclonedx.json" \
  -F "license=$LICENSE_SECRET" \
  -F "current_repo=$GITHUB_REPOSITORY" \
  -F "alert_system=$ALERT_SYSTEM" \
  -F "alert_system_webhook=$ALERT_SYSTEM_WEBHOOK" \
  -F "commit_sha=$COMMIT_SHA" \
  -F "commit_author=$AUTHOR_NAME <$AUTHOR_EMAIL>" \
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
echo "$RESPONSE" | jq '.vulns_cyclonedx_json' > vulns.cyclonedx.json
echo "$RESPONSE" | jq '.prio_vulns' > prio_vulns.json

echo "[+] Vulnerability report received."

# Extract severity counts with defaults
# REVIEW==
# Need moved to the backend
CRIT_COUNT=$(jq '[.vulnerabilities[] | select((.ratings[]?.severity | ascii_downcase) == "critical")] | length' vulns.cyclonedx.json)
HIGH_COUNT=$(jq '[.vulnerabilities[] | select((.ratings[]?.severity | ascii_downcase) == "high")] | length' vulns.cyclonedx.json)
MED_COUNT=$(jq '[.vulnerabilities[] | select((.ratings[]?.severity | ascii_downcase) == "medium")] | length' vulns.cyclonedx.json)
LOW_COUNT=$(jq '[.vulnerabilities[] | select((.ratings[]?.severity | ascii_downcase) == "low")] | length' vulns.cyclonedx.json)
UNKNOWN_COUNT=$(jq '[.vulnerabilities[] | select((.ratings[]?.severity | ascii_downcase) == "unknown")] | length' vulns.cyclonedx.json)

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
  (.vulnerabilities // [])[] 
  | select(
      (.ratings[]?.severity | ascii_downcase) == "critical"
    ) 
  | .id as $ID
  | (.description // "No description available") as $DESC
  | (
      .references[0]?.url
      // (
        if ($ID | test("^GHSA")) then
          "https://github.com/advisories/" + $ID
        elif ($ID | test("^CVE")) then
          "https://cve.mitre.org/cgi-bin/cvename.cgi?name=" + $ID
        else
          "No link available"
        end
      )
    ) as $LINK
  | (
      (.affects[0]?.ref | capture("pkg:(?<type>[^/]+)/(?<name>[^@]+)@(?<version>.+)") 
      // {type: "unknown", name: "unknown", version: "unknown"})
    ) as $PKG
  | "ID: \($ID)
Severity: Critical
Package: \($PKG.name)@\($PKG.version)
Cause: \($DESC)
Link: \($LINK)
---------------------------------------------------------------------------"
' vulns.cyclonedx.json
echo ""
} | tee "summary.md"

sleep 0.2

CRIT_COUNT=$(jq '[.vulnerabilities[] | select((.ratings[]?.severity | ascii_downcase) == "critical")] | length' vulns.cyclonedx.json)
HIGH_COUNT=$(jq '[.vulnerabilities[] | select((.ratings[]?.severity | ascii_downcase) == "high")] | length' vulns.cyclonedx.json)
MED_COUNT=$(jq '[.vulnerabilities[] | select((.ratings[]?.severity | ascii_downcase) == "medium")] | length' vulns.cyclonedx.json)
LOW_COUNT=$(jq '[.vulnerabilities[] | select((.ratings[]?.severity | ascii_downcase) == "low")] | length' vulns.cyclonedx.json)
UNKNOWN_COUNT=$(jq '[.vulnerabilities[] | select((.ratings[]?.severity | ascii_downcase) == "unknown")] | length' vulns.cyclonedx.json)
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

# ==REVIEW

CRIT_COUNT=$(jq '[.vulnerabilities[] | select((.ratings[]?.severity | ascii_downcase) == "critical")] | length' vulns.cyclonedx.json)
echo "$CRIT_COUNT" > crit_count.txt
if [ "$FAIL_ON_CRITICAL" = "true" ] && [ "$CRIT_COUNT" -gt 0 ]; then
  echo "[!] Failing due to $CRIT_COUNT critical vulnerabilities."
fi

echo "[+] Scan Finished"