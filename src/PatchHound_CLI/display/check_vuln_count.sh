critical_vuln_count() {
if [ "$CRIT_COUNT_GRYPE" -gt 0 ] || [ "$CRITICAL_COUNT_SAST" -gt 0 ] || [ "$CRIT_COUNT_TRIVY" -gt 0 ]; then
    print_message "[!]" "Failing on severity CRITICAL" "Critical vulnerability detected."
    FAIL="true"
fi
}

high_vuln_count() {
if [ "$HIGH_COUNT_GRYPE" -gt 0 ] || [ "$HIGH_COUNT_TRIVY" -gt 0 ]; then
    print_message "[!]" "Failing on severity HIGH" "High vulnerability detected."
    FAIL="true"
fi
}

medium_vuln_count() {
if [ "$MED_COUNT_GRYPE" -gt 0 ] || [ "$MED_COUNT_TRIVY" -gt 0 ]; then
    print_message "[!]" "Failing on severity MEDIUM" "Medium vulnerability detected."
    FAIL="true"
fi
}

low_vuln_count() {
if [ "$LOW_COUNT_GRYPE" -gt 0 ] || [ "$LOW_COUNT_TRIVY" -gt 0 ]; then
    print_message "[!]" "Failing on severity LOW" "Low vulnerability detected."
    FAIL="true"
fi
}

unknown_vuln_count() {
if [ "$UNKNOWN_COUNT_GRYPE" -gt 0 ] || [ "$UNKNOWN_COUNT_TRIVY" -gt 0 ]; then
    print_message "[!]" "Failing on severity UNKOWN" "Unknown vulnerability detected."
    FAIL="true"
fi
}