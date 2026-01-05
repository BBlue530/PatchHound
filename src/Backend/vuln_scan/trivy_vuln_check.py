import json

def check_vuln_file_trivy(trivy_report_path, exclusions_file_path):
    with open(trivy_report_path, "r") as f:
        report = json.load(f)

# Keeping this commented for now. If i want the exclusions to get respected here just uncomment.
#    with open(exclusions_file_path, "r") as f:
#        exclusions_data = json.load(f)
#    excluded_ids = {item["vulnerability"] for item in exclusions_data.get("exclusions", [])}

    severity_levels = ["critical", "high", "medium", "low", "unknown"]
    severity_counts = {level: 0 for level in severity_levels}

    # Severities count
    for result in report.get("Results", []):
        for vuln in result.get("Vulnerabilities", []):
#            vuln_id = vuln.get("VulnerabilityID")
#            if vuln_id in excluded_ids:
#                continue
            severity = vuln.get("Severity", "").lower()
            if severity in severity_counts:
                severity_counts[severity] += 1

    trivy_crit_count = severity_counts['critical']
    trivy_high_count = severity_counts['high']
    trivy_medium_count = severity_counts['medium']
    trivy_low_count = severity_counts['low']
    trivy_unknown_count = severity_counts['unknown']

    return trivy_crit_count, trivy_high_count, trivy_medium_count, trivy_low_count, trivy_unknown_count