if [ "$SAST_SCAN" = "true" ]; then
  print_message "[~]" "Running SAST scan..." ""
  semgrep --config=p/security-audit --config=p/ci --json "$TARGET" > "sast_report.json"
else
  print_message "[+]" "Skipping SAST scan" "SAST_SCAN=false"
  echo '{"SAST_SCAN": false, "results": []}' > "sast_report.json"
fi