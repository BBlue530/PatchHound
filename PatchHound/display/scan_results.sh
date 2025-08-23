echo "[~] Generating Summary"

{
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
} | tee summary.md

if [ "$ISSUES_COUNT_SAST" -gt 0 ]; then
  echo "[!] SAST issues found:"
  jq -r '
    (.results // [])[] 
    | "Rule: \(.check_id)
Severity: \(.extra.severity)
Message: \(.extra.message)
Location: \(.path):\(.start.line)
----------------------------------------------------------------------"
  ' sast_report.json | tee summary.md
fi

if [ "$CRIT_COUNT_GRYPE" -gt 0 ]; then
echo "[!] Critical Vulnerabilities Found by Grype"
jq -r '
  (.vulnerabilities // [])[] 
  | select((.ratings // [] | map(.severity // "") | map(ascii_downcase) | index("critical")) != null)
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
' vulns.cyclonedx.json | tee summary.md
fi

if [ "$CRIT_COUNT_TRIVY" -gt 0 ]; then
  echo "[!] Critical Vulnerabilities Found by Trivy"
  jq -r '
    .Results[]?.Vulnerabilities[]?
    | select(.Severity == "CRITICAL")
    | "ID: \(.VulnerabilityID)
Severity: Critical
Package: \(.PkgName)@\(.InstalledVersion)
Cause: \(.Title // .Description // "No description available")
Link: \(.PrimaryURL // "No link available")
----------------------------------------------------------------------"
  ' trivy_report.json | tee summary.md
fi

if [ "$MISCONF_COUNT_TRIVY" -gt 0 ]; then
  echo
  echo "[!] Misconfigurations Found by Trivy"
  jq -r '
    .Results[]?.Misconfigurations[]?
    | "ID: \(.ID)
Severity: \(.Severity)
File: \(.Target)
Check: \(.Title // .Description // "No description")
Resolution: \(.Resolution // "No fix guidance")
Link: \(.PrimaryURL // .References[0] // "No link available")
----------------------------------------------------------------------"
  ' trivy_report.json | tee summary.md
fi

if [ "$SECRET_COUNT_TRIVY" -gt 0 ]; then
  echo
  echo "[!] Secrets Found by Trivy"
  jq -r '
    .Results[]?.Secrets[]?
    | "Rule ID: \(.RuleID)
File: \(.Target)
Severity: \(.Severity)
Title: \(.Title // "No title")
----------------------------------------------------------------------"
  ' trivy_report.json | tee summary.md
fi