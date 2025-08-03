if [ "$SCAN_IMAGE" = "true" ]; then
    echo "[~] Running Trivy scan on image..."
    trivy image --format json -o trivy_report.json "$TARGET"
else
    echo "[~] Running Trivy scan on source repo..."
    trivy fs --scanners vuln,secret,config --format json -o trivy_report.json "$TARGET"
fi

CRIT_COUNT=$(jq '[.Results[]?.Vulnerabilities[]? | select(.Severity == "CRITICAL")] | length' trivy_report.json)

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

if [ "$FAIL_ON_CRITICAL" = "true" ] && [ "$CRIT_COUNT" -gt 0 ]; then
  echo "[!] Trivy found $CRIT_COUNT critical vulnerabilities."
  exit 1
fi