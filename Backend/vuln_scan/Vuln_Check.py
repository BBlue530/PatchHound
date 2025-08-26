import json
import os
import requests

def check_vuln_file(alerts_list, grype_path, alert_path, repo_name, trivy_crit_count, trivy_high_count, trivy_medium_count, trivy_low_count, trivy_unknown_count, trivy_misconf_count, trivy_secret_count, exclusions_file_path):
    if os.path.isfile(alert_path):
        with open(alert_path, "r") as f:
            alert_system_json = json.load(f)

        alert_system_webhook = alert_system_json.get("alert_system_webhook")

    with open(grype_path) as f:
        vuln_data = json.load(f)

    with open(exclusions_file_path, "r") as f:
        exclusions_data = json.load(f)
    excluded_ids = {item["vulnerability"] for item in exclusions_data.get("exclusions", [])}
    
    severity_levels = ["critical", "high", "medium", "low", "unknown"]
    severity_counts = {level: 0 for level in severity_levels}

    # Severities count
    for vuln in vuln_data.get("vulnerabilities", []):
        vuln_ids = [v.get("VulnerabilityID") for v in vuln.get("Vulnerabilities", [])]
        if any(v_id in excluded_ids for v_id in vuln_ids):
            continue
        for rating in vuln.get("ratings", []):
            severity = rating.get("severity", "").lower()
            if severity in severity_counts:
                severity_counts[severity] += 1
    
    crit_count = severity_counts.get("critical", 0)

    if (crit_count > 0 or trivy_crit_count > 0) and "discord" in alert_system_webhook:
        print("[!] Sending Discord alert with severity breakdown...")

        message = {
            "embeds": [{
                "title": "🚨 Vulnerability Severity Report",
                "description": (
                    f"**Repo:** {repo_name}\n\n"
                    f"**Critical:** {severity_counts['critical']}\n"
                    f"**High:** {severity_counts['high']}\n"
                    f"**Medium:** {severity_counts['medium']}\n"
                    f"**Low:** {severity_counts['low']}\n"
                    f"**Unknown:** {severity_counts['unknown']}"
                    f"\n"
                    f"**Trivy Scan:**\n"
                    f"**Critical:** {trivy_crit_count}\n"
                    f"**High:** {trivy_high_count}\n"
                    f"**Medium:** {trivy_medium_count}\n"
                    f"**Low:** {trivy_low_count}\n"
                    f"**Unkown:** {trivy_unknown_count}\n"
                    f"**Misconfiguration:** {trivy_misconf_count}\n"
                    f"**Exposed Secret:** {trivy_secret_count}\n"
                ),
                "color": 16711680
            }]
        }
        response = requests.post(
            alert_system_webhook,
            data=json.dumps(message),
            headers={"Content-Type": "application/json"}
        )
        if response.status_code not in [200, 204]:
            alert_status = f"Failed to send {alert_system_webhook} alert over Discord. Status code: {response.status_code}"
            print(f"[!] {alert_status}")
            alerts_list.append(f"{alert_status}")
        else:
            alert_status = f"Alert sent {alert_system_webhook} alert over Discord. Status code: {response.status_code}"
            print(f"[!] {alert_status}")
            alerts_list.append(f"{alert_status}")

    elif (crit_count > 0 or trivy_crit_count > 0) and "slack" in alert_system_webhook:
        print("[!] Sending Slack alert with severity breakdown...")

        message = {
            "text": ":rotating_light: *Vulnerability Severity Report*",
            "attachments": [
                {
                    "color": "#FF0000",
                    "fields": [
                        {"title": "Repo", "value": repo_name, "short": False},
                        {"title": "Critical", "value": str(severity_counts["critical"]), "short": True},
                        {"title": "High", "value": str(severity_counts["high"]), "short": True},
                        {"title": "Medium", "value": str(severity_counts["medium"]), "short": True},
                        {"title": "Low", "value": str(severity_counts["low"]), "short": True},
                        {"title": "Unknown", "value": str(severity_counts["unknown"]), "short": True},
                    ]
                },
                {
                    "color": "#FF0000",
                    "fields": [
                        {"title": "Trivy Scan", "value": "", "short": False},
                        {"title": "Critical", "value": str(trivy_crit_count), "short": True},
                        {"title": "High", "value": str(trivy_high_count), "short": True},
                        {"title": "Medium", "value": str(trivy_medium_count), "short": True},
                        {"title": "Low", "value": str(trivy_low_count), "short": True},
                        {"title": "Unkown", "value": str(trivy_unknown_count), "short": True},
                        {"title": "Misconfiguration", "value": str(trivy_misconf_count), "short": True},
                        {"title": "Exposed Secret", "value": str(trivy_secret_count), "short": True},
                    ]
                }
            ]
        }
        response = requests.post(
            alert_system_webhook,
            data=json.dumps(message),
            headers={"Content-Type": "application/json"}
        )
        if response.status_code not in [200, 204]:
            alert_status = f"Failed to send {alert_system_webhook} alert over Slack. Status code: {response.status_code}"
            print(f"[!] {alert_status}")
            alerts_list.append(f"{alert_status}")
        else:
            alert_status = f"Alert sent {alert_system_webhook} alert over Slack. Status code: {response.status_code}"
            print(f"[!] {alert_status}")
            alerts_list.append(f"{alert_status}")
    
    else:
        alert_status = f"Failed to send alert for {repo_name}. Alert webhook not set"
        alerts_list.append(f"{alert_status}")
    
    grype_critical_count = severity_counts['critical']
    grype_high_count = severity_counts['high']
    grype_medium_count = severity_counts['medium']
    grype_low_count = severity_counts['low']
    grype_unknown_count = severity_counts['unknown']

    return grype_critical_count, grype_high_count, grype_medium_count, grype_low_count, grype_unknown_count