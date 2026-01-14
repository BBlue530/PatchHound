source "$BASE_DIR/display/check_vuln_count.sh"
FAIL="false"
PATH_TO_RESOURCES_TOKEN_BASE64=$(printf "%s" "$PATH_TO_RESOURCES_TOKEN" | base64 -w 0)
FAIL_ON_VULNERABILITY=$(echo "$FAIL_ON_VULNERABILITY" | tr -d '\r' | xargs)
FAIL_ON_SEVERITY=$(echo "$FAIL_ON_SEVERITY" | tr -d '\r' | xargs)

if [ "$FAIL_ON_VULNERABILITY" = "true" ]; then
  if echo "$FAIL_ON_SEVERITY" | grep -Eq '^[0-9]+(\.[0-9]+)?$'; then
    if [ "$CVSS_COUNT_GRYPE" -gt 0 ] || [ "$CVSS_COUNT_TRIVY" -gt 0 ]; then
      print_message "[!]" "Failing on CVSS: $FAIL_ON_SEVERITY" "Found $((CVSS_COUNT_GRYPE + CVSS_COUNT_TRIVY)) vulnerabilities above CVSS: $FAIL_ON_SEVERITY"
      FAIL="true"
    fi
  else

    case "$FAIL_ON_SEVERITY" in
      "CRITICAL")
        critical_vuln_count
        ;;
      "HIGH")
        critical_vuln_count
        high_vuln_count
        ;;
      "MEDIUM")
        critical_vuln_count
        high_vuln_count
        medium_vuln_count
        ;;
      "LOW")
        critical_vuln_count
        high_vuln_count
        medium_vuln_count
        low_vuln_count
        ;;
      "UNKNOWN")
        critical_vuln_count
        high_vuln_count
        medium_vuln_count
        low_vuln_count
        unknown_vuln_count
        ;;
    esac
  fi
fi

echo "$PATH_TO_RESOURCES_TOKEN_BASE64" > ${PATCHHOUND_SCAN_DATA}path_to_resources_token.txt
print_message "[+]" "Path token" "Path token to access resources sent to backend: 
$PATH_TO_RESOURCES_TOKEN_BASE64"

source "$BASE_DIR/system/cleanup.sh"

if [ "$FAIL" = "true" ]; then
  exit 1
fi