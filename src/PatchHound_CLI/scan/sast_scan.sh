if [ "$SAST_SCAN" = "true" ]; then
  if [ -z "$SAST_RULESETS" ]; then
    print_message "[~]" "Running SAST scan..." ""
    SAST_RULESETS=("${DEFAULT_SAST_RULESETS[@]}")
    semgrep "${SAST_RULESETS[@]}" --json "$TARGET" > "${PATCHHOUND_SCAN_DATA}sast_report.json"
  else
    print_message "[~]" "Running SAST scan with custom ruleset..." ""
    semgrep "${SAST_RULESETS[@]}" --json "$TARGET" > "${PATCHHOUND_SCAN_DATA}sast_report.json"
  fi
  
else
  print_message "[+]" "Skipping SAST scan" "SAST_SCAN=false"
  echo '{"SAST_SCAN": false, "results": []}' > "${PATCHHOUND_SCAN_DATA}sast_report.json"
fi