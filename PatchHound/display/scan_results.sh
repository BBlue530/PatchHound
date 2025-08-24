echo "[~] Generating Summary"

print_message "[i]" "Vulnerability assessment:" "----------------------------------------------------------------------"
print_message "[+]" "Grype Results:" "Critical: $CRIT_COUNT_GRYPE
High: $HIGH_COUNT_GRYPE
Medium: $MED_COUNT_GRYPE
Low: $LOW_COUNT_GRYPE
Unknown: $UNKNOWN_COUNT_GRYPE
----------------------------------------------------------------------"
print_message "[+]" "Trivy Results:" "Critical: $CRIT_COUNT_TRIVY
High: $HIGH_COUNT_TRIVY
Medium: $MED_COUNT_TRIVY
Low: $LOW_COUNT_TRIVY
Unknown: $UNKNOWN_COUNT_TRIVY
Misconfigurations: $MISCONF_COUNT_TRIVY
Exposed Secrets: $SECRET_COUNT_TRIVY
----------------------------------------------------------------------"
print_message "[+]" "SAST Results:" "Critical: $CRITICAL_COUNT_SAST
Issues: $ISSUES_COUNT_SAST
----------------------------------------------------------------------"

if [ "$ISSUES_COUNT_SAST" -gt 0 ]; then
  echo "[!] SAST issues found:"
  jq --slurpfile exclusions exclusions.json -r '
    (.results // [])[]
    | select(.check_id as $id | ($exclusions[0].exclusions | map(.vulnerability) | index($id)) | not)
    | "Rule: \(.check_id)
Severity: \(.extra.severity)
Message: \(.extra.message)
Location: \(.path):\(.start.line)
----------------------------------------------------------------------"
  ' sast_report.json
fi

if [ "$CRIT_COUNT_GRYPE" -gt 0 ]; then
echo "[!] Critical Vulnerabilities Found by Grype"
jq --slurpfile exclusions exclusions.json -r '
  (.vulnerabilities // [])[]
  | select((.ratings // [] | map(.severity // "") | map(ascii_downcase) | index("critical")) != null)
  | select(.id as $id | ($exclusions[0].exclusions | map(.vulnerability) | index($id)) | not)
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
----------------------------------------------------------------------"
' vulns.cyclonedx.json
fi

if [ "$CRIT_COUNT_TRIVY" -gt 0 ]; then
  echo "[!] Critical Vulnerabilities Found by Trivy"
  jq --slurpfile exclusions exclusions.json -r '
    .Results[]?.Vulnerabilities[]?
    | select(.Severity == "CRITICAL")
    | select(.VulnerabilityID as $id | ($exclusions[0].exclusions | map(.vulnerability) | index($id)) | not)
    | "ID: \(.VulnerabilityID)
Severity: Critical
Package: \(.PkgName)@\(.InstalledVersion)
Cause: \(.Title // .Description // "No description available")
Link: \(.PrimaryURL // "No link available")
----------------------------------------------------------------------"
  ' trivy_report.json
fi

if [ "$MISCONF_COUNT_TRIVY" -gt 0 ]; then
  echo
  echo "[!] Misconfigurations Found by Trivy"
  jq --slurpfile exclusions exclusions.json -r '
    .Results[]?.Misconfigurations[]?
    | select(.ID as $id | ($exclusions[0].exclusions | map(.vulnerability) | index($id)) | not)
    | "ID: \(.ID)
Severity: \(.Severity)
File: \(.Target)
Check: \(.Title // .Description // "No description")
Resolution: \(.Resolution // "No fix guidance")
Link: \(.PrimaryURL // .References[0] // "No link available")
----------------------------------------------------------------------"
  ' trivy_report.json
fi

if [ "$SECRET_COUNT_TRIVY" -gt 0 ]; then
  echo
  echo "[!] Secrets Found by Trivy"
  jq --slurpfile exclusions exclusions.json -r '
    .Results[]?.Secrets[]?
    | select(.RuleID as $id | ($exclusions[0].exclusions | map(.vulnerability) | index($id)) | not)
    | "Rule ID: \(.RuleID)
File: \(.Target)
Severity: \(.Severity)
Title: \(.Title // "No title")
----------------------------------------------------------------------"
  ' trivy_report.json
fi