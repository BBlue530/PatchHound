if [ "$TRIVY_SCAN" = "true" ]; then
  if [ "$SCAN_IMAGE" = "true" ]; then
    print_message "[~]" "Running Trivy scan on image..." ""
    "$BASE_DIR_BIN/trivy" image --format json -o trivy_report.json "$TARGET"
  else
    print_message "[~]" "Running Trivy scan on source repo..." ""
    "$BASE_DIR_BIN/trivy" fs --scanners vuln,secret,config --format json -o trivy_report.json "$TARGET"
  fi
else
  print_message "[+]" "Skipping Trivy scan" "TRIVY_SCAN=false"
  echo '{"TRIVY_SCAN": false, "Results": []}' > "trivy_report.json"
fi