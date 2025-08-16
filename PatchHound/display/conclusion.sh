FAIL="false"
PATH_TO_RESOURCES_TOKEN_BASE64=$(printf "%s" "$PATH_TO_RESOURCES_TOKEN" | base64)

echo "$PATH_TO_RESOURCES_TOKEN_BASE64" > path_to_resources_token.txt
print_message "[+]" "Path token" "Path token to access resources sent to backend: 
$PATH_TO_RESOURCES_TOKEN_BASE64"

if [ "$FAIL_ON_CRITICAL" = "true" ]; then

  if [[ "$FAIL_ON_SEVERITY" =~ ^[0-9]+(\.[0-9]+)?$ ]]; then

    FAIL_COUNT_GRYPE=$(jq --argjson t "$FAIL_ON_SEVERITY" '[.vulnerabilities[] | select(.ratings[]?.score? >= $t)] | length' vulns.cyclonedx.json)

    FAIL_COUNT_TRIVY=$(jq --argjson t "$FAIL_ON_SEVERITY" '[.Results[]?.Vulnerabilities[]? | select(.CVSS?.nvd?.V3Score? >= $t or .CVSS?.redhat?.V3Score? >= $t)] | length' trivy_report.json)

    if [ "$FAIL_COUNT_GRYPE" -gt 0 ] || [ "$FAIL_COUNT_TRIVY" -gt 0 ]; then
      print_message "[!]" "Failing on CVSS: $FAIL_ON_SEVERITY" "Found $((FAIL_COUNT_GRYPE + FAIL_COUNT_TRIVY)) vulnerabilities above CVSS: $FAIL_ON_SEVERITY"
      FAIL="true"
    fi
  fi
  
  case "$FAIL_ON_SEVERITY" in
    "CRITICAL")
      if [ "$CRIT_COUNT_GRYPE" -gt 0 ] || [ "$CRITICAL_COUNT_SAST" -gt 0 ] || [ "$CRIT_COUNT_TRIVY" -gt 0 ]; then
        print_message "[!]" "Failing on severity $FAIL_ON_SEVERITY" "Critical vulnerability detected."
        FAIL="true"
      fi
      ;;
    "HIGH")
      if [ "$HIGH_COUNT_GRYPE" -gt 0 ] || [ "$HIGH_COUNT_TRIVY" -gt 0 ]; then
        print_message "[!]" "Failing on severity $FAIL_ON_SEVERITY" "High vulnerability detected."
        FAIL="true"
      fi
      ;;
    "MEDIUM")
      if [ "$MED_COUNT_GRYPE" -gt 0 ] || [ "$MED_COUNT_TRIVY" -gt 0 ]; then
        print_message "[!]" "Failing on severity $FAIL_ON_SEVERITY" "Medium vulnerability detected."
        FAIL="true"
      fi
      ;;
    "LOW")
      if [ "$LOW_COUNT_GRYPE" -gt 0 ] || [ "$LOW_COUNT_TRIVY" -gt 0 ]; then
        print_message "[!]" "Failing on severity $FAIL_ON_SEVERITY" "Low vulnerability detected."
        FAIL="true"
      fi
      ;;
    "UNKNOWN")
      if [ "$UNKNOWN_COUNT_GRYPE" -gt 0 ] || [ "$UNKNOWN_COUNT_TRIVY" -gt 0 ]; then
        print_message "[!]" "Failing on severity $FAIL_ON_SEVERITY" "Unknown vulnerability detected."
        FAIL="true"
      fi
      ;;
  esac
  
  if [ "$FAIL" = "true" ]; then
    exit 1
  fi
fi