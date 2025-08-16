CRITICAL_COUNT_SAST=$(jq '[.results[] | select(.extra.severity == "ERROR" or .extra.severity == "CRITICAL")] | length' sast_report.json)
ISSUES_COUNT_SAST=$(jq '.results | length' "sast_report.json")

if [[ "$FAIL_ON_SEVERITY" =~ ^[0-9]+(\.[0-9]+)?$ ]]; then
    CVSS_COUNT_GRYPE=$(exclusions_filter vulns.cyclonedx.json ".vulnerabilities[] | select(.ratings[]?.score? >= $FAIL_ON_SEVERITY)" "id")
    CVSS_COUNT_TRIVY=$(exclusions_filter trivy_report.json ".Results[]?.Vulnerabilities[]? | select(.CVSS?.nvd?.V3Score? >= $FAIL_ON_SEVERITY or .CVSS?.redhat?.V3Score? >= $FAIL_ON_SEVERITY)" "VulnerabilityID")
fi
    CRIT_COUNT_TRIVY=$(exclusions_filter trivy_report.json '.Results[]?.Vulnerabilities[]? | select(.Severity == "CRITICAL")' "VulnerabilityID")
    HIGH_COUNT_TRIVY=$(exclusions_filter trivy_report.json '.Results[]?.Vulnerabilities[]? | select(.Severity == "HIGH")' "VulnerabilityID")
    MED_COUNT_TRIVY=$(exclusions_filter trivy_report.json '.Results[]?.Vulnerabilities[]? | select(.Severity == "MEDIUM")' "VulnerabilityID")
    LOW_COUNT_TRIVY=$(exclusions_filter trivy_report.json '.Results[]?.Vulnerabilities[]? | select(.Severity == "LOW")' "VulnerabilityID")
    UNKNOWN_COUNT_TRIVY=$(exclusions_filter trivy_report.json '.Results[]?.Vulnerabilities[]? | select(.Severity == "UNKNOWN")' "VulnerabilityID")
    MISCONF_COUNT_TRIVY=$(jq '[.Results[]?.Misconfigurations[]?] | length' trivy_report.json)
    SECRET_COUNT_TRIVY=$(jq '[.Results[]?.Secrets[]?] | length' trivy_report.json)

    CRIT_COUNT_GRYPE=$(exclusions_filter vulns.cyclonedx.json '.vulnerabilities[] | select((.ratings[]?.severity | ascii_downcase) == "critical")' "id")
    HIGH_COUNT_GRYPE=$(exclusions_filter vulns.cyclonedx.json '.vulnerabilities[] | select((.ratings[]?.severity | ascii_downcase) == "high")' "id")
    MED_COUNT_GRYPE=$(exclusions_filter vulns.cyclonedx.json '.vulnerabilities[] | select((.ratings[]?.severity | ascii_downcase) == "medium")' "id")
    LOW_COUNT_GRYPE=$(exclusions_filter vulns.cyclonedx.json '.vulnerabilities[] | select((.ratings[]?.severity | ascii_downcase) == "low")' "id")
    UNKNOWN_COUNT_GRYPE=$(exclusions_filter vulns.cyclonedx.json '.vulnerabilities[] | select((.ratings[]?.severity | ascii_downcase) == "unknown")' "id")