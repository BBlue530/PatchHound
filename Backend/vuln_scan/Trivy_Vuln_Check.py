import json
from logs.Alerts import alert_event_system

def check_vuln_file_trivy(trivy_report_path, alert_path, repo_name):

    with open(trivy_report_path, "r") as f:
        report = json.load(f)

    crit_count = 0
    misconf_count = 0
    secret_count = 0

    for result in report.get("Results", []):
        vulnerabilities = result.get("Vulnerabilities", [])
        crit_count += sum(1 for v in vulnerabilities if v.get("Severity") == "CRITICAL")

        misconfigurations = result.get("Misconfigurations", [])
        misconf_count += len(misconfigurations)

        secrets = result.get("Secrets", [])
        secret_count += len(secrets)

    if crit_count > 0:
        print(f"[!] Trivy found {crit_count} critical vulnerabilities.")

    if misconf_count > 0:
        print(f"[!] Trivy found {misconf_count} misconfigurations.")

    if secret_count > 0:
        print(f"[!] Trivy found {secret_count} secrets.")

    alert = "Trivy Scan Vulnerabilities"
    message = {
            "embeds": [{
                "description": (
                    f"**Repo:** {repo_name}\n\n"
                    f"**Critical:** {crit_count}\n"
                    f"**Misconfiguration:** {misconf_count}\n"
                    f"**Exposed Secret:** {secret_count}\n"
                ),
                "color": 16711680
            }]
        }
    alert_event_system(message, alert, alert_path)