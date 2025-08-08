CRITICAL_COUNT=$(jq '[.results[] | select(.extra.severity == "ERROR" or .extra.severity == "CRITICAL")] | length' sast_report.json)
ISSUES_COUNT=$(jq '.results | length' "sast_report.json")

echo "[i] Semgrep found $ISSUES_COUNT issues."

if [ "$ISSUES_COUNT" -gt 0 ]; then
  echo "[!] SAST issues found:"
  jq -r '
    (.results // [])[] 
    | "Rule: \(.check_id)
Severity: \(.extra.severity)
Message: \(.extra.message)
Location: \(.path):\(.start.line)
---------------------------------------------------------------------------"
  ' sast_report.json
else
  echo "[+] No SAST issues found."
fi

if [ "$FAIL_ON_CRITICAL" = "true" ] && [ "$CRITICAL_COUNT" -gt 0 ]; then
  echo "[!] Failing due to $CRITICAL_COUNT critical issues."
  exit 1
fi


CRIT_COUNT=$(jq '[.Results[]?.Vulnerabilities[]? | select(.Severity == "CRITICAL")] | length' trivy_report.json)
if [ "$CRIT_COUNT" -gt 0 ]; then
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
  ' trivy_report.json
fi

MISCONF_COUNT=$(jq '[.Results[]?.Misconfigurations[]?] | length' trivy_report.json)
if [ "$MISCONF_COUNT" -gt 0 ]; then
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
  ' trivy_report.json
fi

SECRET_COUNT=$(jq '[.Results[]?.Secrets[]?] | length' trivy_report.json)
if [ "$SECRET_COUNT" -gt 0 ]; then
  echo
  echo "[!] Secrets Found by Trivy"
  jq -r '
    .Results[]?.Secrets[]?
    | "Rule ID: \(.RuleID)
File: \(.Target)
Severity: \(.Severity)
Title: \(.Title // "No title")
---------------------------------------------------------------------------"
  ' trivy_report.json
fi

if [ "$FAIL_ON_CRITICAL" = "true" ] && [ "$CRIT_COUNT" -gt 0 ]; then
  echo "[!] Trivy found $CRIT_COUNT critical vulnerabilities."
  exit 1
fi

if [ "$FAIL_ON_CRITICAL" = "true" ] && [ "$MISCONF_COUNT" -gt 0 ]; then
  echo "[!] Trivy found $MISCONF_COUNT misconfigurations."
  exit 1
fi

if [ "$FAIL_ON_CRITICAL" = "true" ] && [ "$SECRET_COUNT" -gt 0 ]; then
  echo "[!] Trivy found $SECRET_COUNT secrets."
  exit 1
fi