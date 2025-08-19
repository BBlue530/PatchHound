import json

def check_vuln_file_trivy(trivy_report_path, exclusions_file_path):
    with open(trivy_report_path, "r") as f:
        report = json.load(f)
    
    with open(exclusions_file_path, "r") as f:
        exclusions_data = json.load(f)
    excluded_ids = {item["vulnerability"] for item in exclusions_data.get("exclusions", [])}

    trivy_crit_count = 0
    trivy_misconf_count = 0
    trivy_secret_count = 0

    for result in report.get("Results", []):
        for v in result.get("Vulnerabilities", []):
            if v.get("VulnerabilityID") in excluded_ids:
                continue
            if v.get("Severity") == "CRITICAL":
                trivy_crit_count += 1

        for m in result.get("Misconfigurations", []):
            if m.get("ID") in excluded_ids:
                continue
            trivy_misconf_count += 1

        for s in result.get("Secrets", []):
            if s.get("RuleID") in excluded_ids:
                continue
            trivy_secret_count += 1

    return trivy_crit_count, trivy_misconf_count, trivy_secret_count