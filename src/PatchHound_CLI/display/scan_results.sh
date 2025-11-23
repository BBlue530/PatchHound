echo "[~] Generating Summary"
source "$BASE_DIR/display/vulnerabilities_info.sh"

print_message "[i]" "Vulnerability assessment:" "----------------------------------------------------------------------"
print_message "[+]" "Grype Results:" "Critical: $CRIT_COUNT_GRYPE
High: $HIGH_COUNT_GRYPE
Medium: $MED_COUNT_GRYPE
Low: $LOW_COUNT_GRYPE
Unknown: $UNKNOWN_COUNT_GRYPE
----------------------------------------------------------------------"
print_message "[+]" "Trivy Results:" "Critical: $CRIT_COUNT_TRIVY
High: $HIGH_COUNT_TRIVY
Medium: $MED_COUNT_TRIVY
Low: $LOW_COUNT_TRIVY
Unknown: $UNKNOWN_COUNT_TRIVY
Misconfigurations: $MISCONF_COUNT_TRIVY
Exposed Secrets: $SECRET_COUNT_TRIVY
----------------------------------------------------------------------"
print_message "[+]" "SAST Results:" "Critical: $CRITICAL_COUNT_SAST
Issues: $ISSUES_COUNT_SAST
----------------------------------------------------------------------"

if [[ "$FAIL_ON_SEVERITY" =~ ^[0-9]+(\.[0-9]+)?$ ]]; then
  print_cvss_vulns "$FAIL_ON_SEVERITY"
fi
FAIL_ON_SEVERITY=$(echo "$FAIL_ON_SEVERITY" | tr -d '\r' | xargs)
case "$FAIL_ON_SEVERITY" in
  "CRITICAL")
    print_critical_vulns
    ;;
  "HIGH")
    print_critical_vulns
    print_high_vulns
    ;;
  "MEDIUM")
    print_critical_vulns
    print_high_vulns
    print_medium_vulns
    ;;
  "LOW")
    print_critical_vulns
    print_high_vulns
    print_medium_vulns
    print_low_vulns
    ;;
  "UNKNOWN")
    print_critical_vulns
    print_high_vulns
    print_medium_vulns
    print_low_vulns
    print_unkown_vulns
    ;;
esac

print_trivy_misconf_secrets