#!/bin/bash
set -e

CONFIG_FILE="${1:-scan.config}"

echo "[~] Installing dependencies..."

sudo apt-get update && sudo apt-get install -y jq curl
curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh -s -- -b /usr/local/bin

if [ -n "$GHCR_PAT" ]; then
  echo "$GHCR_PAT" | docker login ghcr.io -u "$GITHUB_ACTOR" --password-stdin
else
  echo "[!] GHCR_PAT not set. Skipping Docker auth."
fi

if [ -f "$CONFIG_FILE" ]; then
  source "$CONFIG_FILE"
else
  echo "[-] Config file '$CONFIG_FILE' not found!"
  exit 1
fi

if [[ -z "$SBOM_SCAN_API_URL" || -z "$LICENSE_SECRET" ]]; then
  echo "[!] Missing SBOM_SCAN_API_URL or LICENSE_SECRET. Exiting."
  exit 2
fi

echo "COMMIT_SHA=$COMMIT_SHA"
echo "AUTHOR_NAME=$AUTHOR_NAME"
echo "AUTHOR_EMAIL=$AUTHOR_EMAIL"
echo "GITHUB_REPOSITORY=$GITHUB_REPOSITORY"
echo "ALERT_WEBHOOK=$ALERT_WEBHOOK"
echo "SBOM_SCAN_API_URL=$SBOM_SCAN_API_URL"


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
  -F "alert_system_webhook=$ALERT_WEBHOOK" \
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

echo "$CRIT_COUNT" > crit_count.txt
CRIT_COUNT=$(jq '[.vulnerabilities[] | select((.ratings[]?.severity | ascii_downcase) == "critical")] | length' vulns.cyclonedx.json)
if [ "$FAIL_ON_CRITICAL" = "true" ] && [ "$CRIT_COUNT" -gt 0 ]; then
  echo "[!] Failing due to $CRIT_COUNT critical vulnerabilities."
  exit 1
fi

echo "[+] Scan Finished"