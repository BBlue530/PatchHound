import json
import os

def check_vuln_file(grype_path, exclusions_file_path):
    with open(grype_path) as f:
        vuln_data = json.load(f)

# Keeping this commented for now. If i want the exclusions to get respected here just uncomment.
#    with open(exclusions_file_path, "r") as f:
#        exclusions_data = json.load(f)
#    excluded_ids = {item["vulnerability"] for item in exclusions_data.get("exclusions", [])}
    
    severity_levels = ["critical", "high", "medium", "low", "unknown"]
    severity_counts = {level: 0 for level in severity_levels}

    # Severities count
    for vuln in vuln_data.get("vulnerabilities", []):
#        vuln_id = vuln.get("id")
#        if vuln_id in excluded_ids:
#            continue
        severity = vuln.get("severity", "").lower()
        if severity in severity_counts:
            severity_counts[severity] += 1
    
    grype_critical_count = severity_counts['critical']
    grype_high_count = severity_counts['high']
    grype_medium_count = severity_counts['medium']
    grype_low_count = severity_counts['low']
    grype_unknown_count = severity_counts['unknown']

    return grype_critical_count, grype_high_count, grype_medium_count, grype_low_count, grype_unknown_count