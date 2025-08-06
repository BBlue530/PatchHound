import json

def check_vuln_file_trivy(trivy_report_path):

    with open(trivy_report_path, "r") as f:
        report = json.load(f)

    trivy_crit_count = 0
    trivy_misconf_count = 0
    trivy_secret_count = 0

    for result in report.get("Results", []):
        vulnerabilities = result.get("Vulnerabilities", [])
        trivy_crit_count += sum(1 for v in vulnerabilities if v.get("Severity") == "CRITICAL")

        misconfigurations = result.get("Misconfigurations", [])
        trivy_misconf_count += len(misconfigurations)

        secrets = result.get("Secrets", [])
        trivy_secret_count += len(secrets)

    return trivy_crit_count, trivy_misconf_count, trivy_secret_count