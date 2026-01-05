from logs.audit_trail import audit_trail_event

def vuln_count(audit_trail, semgrep_sast_report_json, trivy_report_json, exclusions_file_json, excluded_vuln_counter, excluded_misconf_counter, excluded_exposed_secret_counter, grype_critical_count, grype_high_count, grype_medium_count, grype_low_count, grype_unknown_count, trivy_crit_count, trivy_high_count, trivy_medium_count, trivy_low_count, trivy_unknown_count, vuln_counter, misconf_counter, exposed_secret_counter, excluded_kev_vuln_counter, kev_vuln_counter):
    sast_issue_count = 0

# Keeping this commented for now. If i want the exclusions to get respected here just uncomment.
#    excluded_ids = {
#        e.get("vulnerability")
#        for e in exclusions_file_json.get("exclusions", [])
#        if e.get("vulnerability")
#    }

    def add_vuln(key, sast_issue_count):
#        if key in excluded_ids:
#            return sast_issue_count
        return sast_issue_count + 1

    if not semgrep_sast_report_json.get("SAST_SCAN"):
        for issue in semgrep_sast_report_json.get("results", []):
            fingerprint = (
                issue.get("fingerprint")
                or issue.get("extra", {}).get("fingerprint")
                or "unknown_fingerprint"
            )
            unique_key = f"semgrep_{issue.get('check_id', 'unknown_rule')}_{fingerprint}"
            sast_issue_count = add_vuln(unique_key, sast_issue_count)

    vulns_found = {
        "excluded_vuln_counter": excluded_vuln_counter,
        "excluded_misconf_counter": excluded_misconf_counter,
        "excluded_exposed_secret_counter": excluded_exposed_secret_counter,
        "excluded_kev_vuln_counter": excluded_kev_vuln_counter,
        "total_vuln_counter": vuln_counter,
        "kev_vuln_counter": kev_vuln_counter,
        "grype_critical": grype_critical_count,
        "grype_high": grype_high_count,
        "grype_medium": grype_medium_count,
        "grype_low": grype_low_count,
        "grype_unknown": grype_unknown_count,
        "trivy_critical": trivy_crit_count,
        "trivy_high": trivy_high_count,
        "trivy_medium": trivy_medium_count,
        "trivy_low": trivy_low_count,
        "trivy_unknown": trivy_unknown_count,
        "trivy_misconfigurations": misconf_counter,
        "trivy_secrets": exposed_secret_counter,
        "sast_issues": sast_issue_count
    }

    audit_trail_event(audit_trail, "VULN_COUNT", {
            "vulnerabilities_count": vulns_found
        })

    if semgrep_sast_report_json.get("SAST_SCAN") is False:
        audit_trail_event(audit_trail, "SAST_SCAN", {
            "status": "skipped"
        })
        vulns_found["sast_scan_skipped"] = True

    if trivy_report_json.get("TRIVY_SCAN") is False:
        audit_trail_event(audit_trail, "TRIVY_SCAN", {
            "status": "skipped"
        })
        vulns_found["trivy_scan_skipped"] = True

    return vulns_found