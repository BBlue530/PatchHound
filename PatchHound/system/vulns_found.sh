source "$BASE_DIR/utils/exclusion_filter.sh"

EXCLUSIONS_FILE=$(find_exclusions_file) || { echo "exclusions.json not found"; exit 1; }

if [[ -f sast_report.json ]]; then
    CRITICAL_COUNT_SAST=$(jq '[.results[] | select(.extra.severity == "ERROR" or .extra.severity == "CRITICAL")] | length' sast_report.json)
    ISSUES_COUNT_SAST=$(jq '.results | length' "sast_report.json")
else
    CRITICAL_COUNT_SAST=0
    ISSUES_COUNT_SAST=0
fi

if [[ "$FAIL_ON_SEVERITY" =~ ^[0-9]+(\.[0-9]+)?$ ]]; then
    if [[ -f vulns.cyclonedx.json ]]; then
        CVSS_COUNT_GRYPE=$(exclusions_filter vulns.cyclonedx.json ".vulnerabilities[] | select(.ratings[]?.score? >= $FAIL_ON_SEVERITY)" "id")
    else
        CVSS_COUNT_GRYPE=0
    fi
    if [[ -f trivy_report.json ]]; then
        CVSS_COUNT_TRIVY=$(exclusions_filter trivy_report.json ".Results[]?.Vulnerabilities[]? | select(.CVSS?.nvd?.V3Score? >= $FAIL_ON_SEVERITY or .CVSS?.redhat?.V3Score? >= $FAIL_ON_SEVERITY)" "VulnerabilityID")
    else
        CVSS_COUNT_TRIVY=0
    fi
fi
if [[ -f trivy_report.json ]]; then
    CRIT_COUNT_TRIVY=$(exclusions_filter trivy_report.json '.Results[]?.Vulnerabilities[]? | select(.Severity == "CRITICAL")' "VulnerabilityID")
    HIGH_COUNT_TRIVY=$(exclusions_filter trivy_report.json '.Results[]?.Vulnerabilities[]? | select(.Severity == "HIGH")' "VulnerabilityID")
    MED_COUNT_TRIVY=$(exclusions_filter trivy_report.json '.Results[]?.Vulnerabilities[]? | select(.Severity == "MEDIUM")' "VulnerabilityID")
    LOW_COUNT_TRIVY=$(exclusions_filter trivy_report.json '.Results[]?.Vulnerabilities[]? | select(.Severity == "LOW")' "VulnerabilityID")
    UNKNOWN_COUNT_TRIVY=$(exclusions_filter trivy_report.json '.Results[]?.Vulnerabilities[]? | select(.Severity == "UNKNOWN")' "VulnerabilityID")
    MISCONF_COUNT_TRIVY=$(jq '[.Results[]?.Misconfigurations[]?] | length' trivy_report.json)
    SECRET_COUNT_TRIVY=$(jq '[.Results[]?.Secrets[]?] | length' trivy_report.json)
else
    CRIT_COUNT_TRIVY=0
    HIGH_COUNT_TRIVY=0
    MED_COUNT_TRIVY=0
    LOW_COUNT_TRIVY=0
    UNKNOWN_COUNT_TRIVY=0
    MISCONF_COUNT_TRIVY=0
    SECRET_COUNT_TRIVY=0
fi
if [[ -f vulns.cyclonedx.json ]]; then
    CRIT_COUNT_GRYPE=$(exclusions_filter vulns.cyclonedx.json '.vulnerabilities[] | select((.ratings[]?.severity | ascii_downcase) == "critical")' "id")
    HIGH_COUNT_GRYPE=$(exclusions_filter vulns.cyclonedx.json '.vulnerabilities[] | select((.ratings[]?.severity | ascii_downcase) == "high")' "id")
    MED_COUNT_GRYPE=$(exclusions_filter vulns.cyclonedx.json '.vulnerabilities[] | select((.ratings[]?.severity | ascii_downcase) == "medium")' "id")
    LOW_COUNT_GRYPE=$(exclusions_filter vulns.cyclonedx.json '.vulnerabilities[] | select((.ratings[]?.severity | ascii_downcase) == "low")' "id")
    UNKNOWN_COUNT_GRYPE=$(exclusions_filter vulns.cyclonedx.json '.vulnerabilities[] | select((.ratings[]?.severity | ascii_downcase) == "unknown")' "id")
else
    CRIT_COUNT_GRYPE=0
    HIGH_COUNT_GRYPE=0
    MED_COUNT_GRYPE=0
    LOW_COUNT_GRYPE=0
    UNKNOWN_COUNT_GRYPE=0
fi