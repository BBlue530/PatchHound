echo "[~] Running SAST scan..."

semgrep --config=p/security-audit --config=p/ci --json "$REPO_DIR" > "sast_report.json"

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
