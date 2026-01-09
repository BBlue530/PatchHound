import json
from logs.audit_trail import audit_trail_event

def check_vuln_files(audit_trail, grype_path, trivy_report_path, semgrep_sast_report_path, exclusions_file_path, excluded_vuln_counter, excluded_misconf_counter, excluded_exposed_secret_counter, vuln_counter, misconf_counter, exposed_secret_counter, excluded_kev_vuln_counter, kev_vuln_counter):
    vulns_found = {}

    with open(grype_path) as f:
        grype_vuln_data = json.load(f)

    with open(trivy_report_path, "r") as f:
        trivy_vuln_data = json.load(f)

    with open(semgrep_sast_report_path, "r") as f:
        semgrep_sast_vuln_data = json.load(f)

# Keeping this for now. If i want the exclusions to get respected just uncomment in the methods.
    with open(exclusions_file_path, "r") as f:
        exclusions_file_data = json.load(f)

    excluded_ids = {
        e.get("vulnerability")
        for e in exclusions_file_data.get("exclusions", [])
        if e.get("vulnerability")
    }

    severity_levels = ["critical", "high", "medium", "low", "unknown"]
    severity_counts = {level: 0 for level in severity_levels}

    vulns_found = check_vuln_file_grype(grype_vuln_data, excluded_ids, vulns_found, severity_counts)

    vulns_found = check_vuln_file_trivy(trivy_vuln_data, excluded_ids, vulns_found, severity_counts)

    vulns_found = check_vuln_file_semgrep(semgrep_sast_vuln_data, excluded_ids, vulns_found)

    audit_trail_event(audit_trail, "VULN_COUNT", {
            "vulnerabilities_count": vulns_found
        })

    if semgrep_sast_vuln_data.get("SAST_SCAN") is False:
        audit_trail_event(audit_trail, "SAST_SCAN", {
            "status": "skipped"
        })
        vulns_found["sast_scan_skipped"] = True

    if trivy_vuln_data.get("TRIVY_SCAN") is False:
        audit_trail_event(audit_trail, "TRIVY_SCAN", {
            "status": "skipped"
        })
        vulns_found["trivy_scan_skipped"] = True

    vulns_found["excluded_vuln_counter"] = excluded_vuln_counter
    vulns_found["excluded_misconf_counter"] = excluded_misconf_counter
    vulns_found["excluded_exposed_secret_counter"] = excluded_exposed_secret_counter
    vulns_found["excluded_kev_vuln_counter"] = excluded_kev_vuln_counter
    vulns_found["total_vuln_counter"] = vuln_counter
    vulns_found["kev_vuln_counter"] = kev_vuln_counter
    vulns_found["misconf_counter"] = misconf_counter
    vulns_found["exposed_secret_counter"] = exposed_secret_counter

    return vulns_found

def check_vuln_file_grype(grype_vuln_data, excluded_ids, vulns_found, severity_counts):

    for vuln in grype_vuln_data.get("vulnerabilities", []):
#        vuln_id = vuln.get("id")
#        if vuln_id in excluded_ids:
#            continue
        severity = vuln.get("severity", "").lower()
        if severity in severity_counts:
            severity_counts[severity] += 1

    vulns_found["grype_critical_count"] = severity_counts['critical']
    vulns_found["grype_high_count"] = severity_counts['high']
    vulns_found["grype_medium_count"] = severity_counts['medium']
    vulns_found["grype_low_count"] = severity_counts['low']
    vulns_found["grype_unknown_count"] = severity_counts['unknown']

    return vulns_found

def check_vuln_file_trivy(trivy_vuln_data, excluded_ids, vulns_found, severity_counts):

    for result in trivy_vuln_data.get("Results", []):
        for vuln in result.get("Vulnerabilities", []):
#            vuln_id = vuln.get("VulnerabilityID")
#            if vuln_id in excluded_ids:
#                continue
            severity = vuln.get("Severity", "").lower()
            if severity in severity_counts:
                severity_counts[severity] += 1

    vulns_found["trivy_crit_count"] = severity_counts['critical']
    vulns_found["trivy_high_count"] = severity_counts['high']
    vulns_found["trivy_medium_count"] = severity_counts['medium']
    vulns_found["trivy_low_count"] = severity_counts['low']
    vulns_found["trivy_unknown_count"] = severity_counts['unknown']

    return vulns_found

def check_vuln_file_semgrep(semgrep_sast_vuln_data, excluded_ids, vulns_found):
    sast_issue_count = 0

    if not semgrep_sast_vuln_data.get("SAST_SCAN"):
        for issue in semgrep_sast_vuln_data.get("results", []):
            fingerprint = (
                issue.get("fingerprint")
                or issue.get("extra", {}).get("fingerprint")
                or "unknown_fingerprint"
            )
#            unique_key = f"semgrep_{issue.get('check_id', 'unknown_rule')}_{fingerprint}"
#            if unique_key in excluded_ids:
#                continue
            sast_issue_count + 1

    vulns_found["sast_issue_count"] = sast_issue_count

    return vulns_found