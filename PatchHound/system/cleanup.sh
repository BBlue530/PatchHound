if [ "$CLEANUP" = "true" ]; then
  print_message "[~]" "Running cleanup..." ""
  rm -f sast_report.json vulns.cyclonedx.json trivy_report.json
fi