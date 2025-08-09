echo "[~] Generating Summary"

{
echo "[i] Vulnerability assessment:"
echo "---------------------------------------------------------------------------"
echo "[+] Grype Results:"
echo "Critical: $CRIT_COUNT_GRYPE"
echo "High: $HIGH_COUNT_GRYPE"
echo "Medium: $MED_COUNT_GRYPE"
echo "Low: $LOW_COUNT_GRYPE"
echo "Unknown: $UNKNOWN_COUNT_GRYPE"
echo "---------------------------------------------------------------------------"
echo "[+] Trivy Results:"
echo "Critical: $CRIT_COUNT_TRIVY"
echo "High: $HIGH_COUNT_TRIVY"
echo "Medium: $MED_COUNT_TRIVY"
echo "Low: $LOW_COUNT_TRIVY"
echo "Unknown: $UNKNOWN_COUNT_TRIVY"
echo "Misconfigurations: $MISCONF_COUNT_TRIVY"
echo "Exposed Secrets: $SECRET_COUNT_TRIVY"
echo "---------------------------------------------------------------------------"
echo "[+] SAST Results:"
echo "Critical: $CRITICAL_COUNT_SAST"
echo "Issues: $ISSUES_COUNT_SAST"
echo "---------------------------------------------------------------------------"
} | tee summary.md

if [ "$ISSUES_COUNT_SAST" -gt 0 ]; then
  echo "[!] SAST issues found:"
  jq -r '
    (.results // [])[] 
    | "Rule: \(.check_id)
Severity: \(.extra.severity)
Message: \(.extra.message)
Location: \(.path):\(.start.line)
---------------------------------------------------------------------------"
  ' sast_report.json | tee summary.md
fi

if ["$CRIT_COUNT_GRYPE" -gt 0 ]; then
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
fi

if [ "$CRIT_COUNT_TRIVY" -gt 0 ]; then
  echo
  echo "[!] Critical Vulnerabilities Found by Trivy"
  jq -r '
    .Results[]?.Vulnerabilities[]?
    | select(.Severity == "CRITICAL")
    | "ID: \(.VulnerabilityID)
Severity: Critical
Package: \(.PkgName)@\(.InstalledVersion)
Cause: \(.Title // .Description // "No description available")
Link: \(.PrimaryURL // "No link available")
---------------------------------------------------------------------------"
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
---------------------------------------------------------------------------"
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
---------------------------------------------------------------------------"
  ' trivy_report.json | tee summary.md
fi