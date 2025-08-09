echo "[+] Vulnerability report received."

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

echo "[~] Generating Summary"
jq -r '
  (.vulnerabilities // [])[] 
  | select((.ratings[]?.severity | ascii_downcase) == "critical") 
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
' vulns.cyclonedx.json | tee summary.md

PATH_TO_RESOURCES_TOKEN_BASE64=$(printf "%s" "$PATH_TO_RESOURCES_TOKEN" | base64)

echo "$PATH_TO_RESOURCES_TOKEN_BASE64" > path_to_resources_token.txt
echo "[+] Token to access resources sent to backend: $PATH_TO_RESOURCES_TOKEN_BASE64"

echo "$CRIT_COUNT" > crit_count.txt

if [ "$FAIL_ON_CRITICAL" = "true" ] && [ "$CRIT_COUNT" -gt 0 ]; then
  echo "[!] Failing due to $CRIT_COUNT critical vulnerabilities."
  exit 1
fi