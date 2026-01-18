import json
import requests
import os
from logs.audit_trail import audit_trail_event
from logs.export_logs import log_exporter
from alerts.alert_helpers import check_alert_status
from utils.helpers import load_file_data

def check_alert_on_severity(audit_trail, alerts_list, alert_path, fail_on_severity_path, repo_name, grype_path, trivy_report_path, semgrep_sast_report_path, exclusions_file_path):
    severity_levels = ["critical", "high", "medium", "low", "unknown"]
    severity_counts_trivy = {level: 0 for level in severity_levels}
    severity_counts_grype = {level: 0 for level in severity_levels}

    trivy_crit_count = 0
    trivy_high_count = 0
    trivy_medium_count = 0
    trivy_low_count = 0
    trivy_unknown_count = 0
    trivy_misconf_count = 0
    trivy_secret_count = 0

    grype_critical_count = 0
    grype_high_count = 0
    grype_medium_count = 0
    grype_low_count = 0
    grype_unknown_count = 0

    semgrep_issue_count = 0

    grype_data = load_file_data(grype_path)

    trivy_data = load_file_data(trivy_report_path)

    semgrep_data = load_file_data(semgrep_sast_report_path)

    exclusions_data = load_file_data(exclusions_file_path)

    if os.path.isfile(alert_path):
        alert_system_json = load_file_data(alert_path)

        alert_system_webhook = alert_system_json.get("alert_system_webhook")

    if os.path.isfile(fail_on_severity_path):
        fail_on_severity_json = load_file_data(fail_on_severity_path)

        fail_on_severity = fail_on_severity_json.get("fail_on_severity")

    excluded_ids = {
        e.get("vulnerability")
        for e in exclusions_data.get("exclusions", [])
        if e.get("vulnerability")
    }

    # These severities counters respect the exclusions
    for vuln in grype_data.get("vulnerabilities", []):
        vuln_id = vuln.get("id")
        if vuln_id in excluded_ids:
            continue
        for rating in vuln.get("ratings", []):
            severity = rating.get("severity", "").lower()
            if severity in severity_counts_grype:
                severity_counts_grype[severity] += 1

    for result in trivy_data.get("Results", []):
        for vuln in result.get("Vulnerabilities", []):
            vuln_id = vuln.get("VulnerabilityID")
            if vuln_id in excluded_ids:
                continue
            severity = vuln.get("Severity", "").lower()
            if severity in severity_counts_trivy:
                severity_counts_trivy[severity] += 1
        
        for misconfig in result.get("Misconfigurations", []):
            misconfig_id = misconfig.get("ID")
            if misconfig_id in excluded_ids:
                continue
            trivy_misconf_count += 1

        for secrets in result.get("Secrets", []):
            secret_id = secrets.get("ID")
            if secret_id in excluded_ids:
                continue
            trivy_secret_count += 1

    if not semgrep_data.get("SAST_SCAN"):
        for issue in semgrep_data.get("results", []):
            fingerprint = (
                issue.get("fingerprint")
                or issue.get("extra", {}).get("fingerprint")
                or "unknown_fingerprint"
            )
            unique_key = f"semgrep_{issue.get('check_id', 'unknown_rule')}_{fingerprint}"
            if unique_key in excluded_ids:
                continue
            semgrep_issue_count += 1

    if fail_on_severity:
        if isinstance(fail_on_severity, (int, float)):
            if fail_on_severity >= 9:
                alert_on_severity = "critical"
            elif fail_on_severity >= 7:
                alert_on_severity = "high"
            elif fail_on_severity >= 4:
                alert_on_severity = "medium"
            elif fail_on_severity >= 0.1:
                alert_on_severity = "low"
            else:
                alert_on_severity = "unknown"
        else:
            alert_on_severity = fail_on_severity.lower()
    else:
        alert_on_severity = "critical"
    
    trivy_crit_count = severity_counts_trivy['critical']
    trivy_high_count = severity_counts_trivy['high']
    trivy_medium_count = severity_counts_trivy['medium']
    trivy_low_count = severity_counts_trivy['low']
    trivy_unknown_count = severity_counts_trivy['unknown']

    grype_critical_count = severity_counts_grype['critical']
    grype_high_count = severity_counts_grype['high']
    grype_medium_count = severity_counts_grype['medium']
    grype_low_count = severity_counts_grype['low']
    grype_unknown_count = severity_counts_grype['unknown']

    alert_status = check_alert_status(alert_on_severity, grype_critical_count, grype_high_count, grype_medium_count, grype_low_count, grype_unknown_count, trivy_crit_count, trivy_high_count, trivy_medium_count, trivy_low_count, trivy_unknown_count)

    if alert_status and "discord" in alert_system_webhook:
        print("[!] Sending Discord alert with severity breakdown...")

        message = {
            "embeds": [{
                "title": "🚨 Vulnerability Severity Report",
                "description": (
                    f"**Repo:** {repo_name}\n\n"
                    f"━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n"
                    f"**Grype Scan:**\n"
                    f"**Critical:** {grype_critical_count}\n"
                    f"**High:** {grype_high_count}\n"
                    f"**Medium:** {grype_medium_count}\n"
                    f"**Low:** {grype_low_count}\n"
                    f"**Unknown:** {grype_unknown_count}"
                    f"━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n"
                    f"**Trivy Scan:**\n"
                    f"**Critical:** {trivy_crit_count}\n"
                    f"**High:** {trivy_high_count}\n"
                    f"**Medium:** {trivy_medium_count}\n"
                    f"**Low:** {trivy_low_count}\n"
                    f"**Unkown:** {trivy_unknown_count}\n"
                    f"**Misconfiguration:** {trivy_misconf_count}\n"
                    f"**Exposed Secret:** {trivy_secret_count}\n"
                    f"━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n"
                    f"**Semgrep Scan:**\n"
                    f"**Issues:** {semgrep_issue_count}\n"
                    f"━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n"
                ),
                "color": 16711680
            }]
        }
        response = requests.post(
            alert_system_webhook,
            data=json.dumps(message),
            headers={"Content-Type": "application/json"}
        )
        audit_trail_event(audit_trail, "ALERT_SYSTEM", {
            "status_code": response.status_code,
            "webhook": "discord",
            "message": "vulnerability severity report summary"
        })
        if response.status_code not in [200, 204]:
            alert_status = f"Failed to send {alert_system_webhook} alert over Discord. Status code: {response.status_code}"
            new_entry = {
                "message": alert_status,
                "level": "error",
                "module": "discord_alert",
            }
            log_exporter(new_entry)

            print(f"[!] {alert_status}")
            audit_trail_event(audit_trail, "ALERT_SYSTEM", {
                "status_code": response.status_code,
                "webhook": "discord",
                "message": "vulnerability severity report summary"
            })
            alerts_list.append(f"{alert_status}")
        else:
            alert_status = f"Alert sent {alert_system_webhook} alert over Discord. Status code: {response.status_code}"
            new_entry = {
                "message": alert_status,
                "level": "info",
                "module": "discord_alert",
            }
            log_exporter(new_entry)

            print(f"[!] {alert_status}")
            audit_trail_event(audit_trail, "ALERT_SYSTEM", {
            "status_code": response.status_code,
            "webhook": "discord",
            "message": "vulnerability severity report summary",
            "status_code": response.status_code
        })
            alerts_list.append(f"{alert_status}")

    elif alert_status and "slack" in alert_system_webhook:
        print("[!] Sending Slack alert with severity breakdown...")

        message = {
            "text": ":rotating_light: *Vulnerability Severity Report*",
            "attachments": [
                {
                    "color": "#FF0000",
                    "fields": [
                        {"title": "Repo", "value": repo_name, "short": False},
                        {"title": "Critical", "value": str(grype_critical_count), "short": True},
                        {"title": "High", "value": str(grype_high_count), "short": True},
                        {"title": "Medium", "value": str(grype_medium_count), "short": True},
                        {"title": "Low", "value": str(grype_low_count), "short": True},
                        {"title": "Unknown", "value": str(grype_unknown_count), "short": True},
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
                },
                {
                    "color": "#FF0000",
                    "fields": [
                        {"title": "Semgrep Scan", "value": "", "short": False},
                        {"title": "Issues", "value": str(semgrep_issue_count), "short": True},
                    ]
                }
            ]
        }
        response = requests.post(
            alert_system_webhook,
            data=json.dumps(message),
            headers={"Content-Type": "application/json"}
        )
        audit_trail_event(audit_trail, "ALERT_SYSTEM", {
            "status_code": response.status_code,
            "webhook": "slack",
            "message": "vulnerability severity report summary",
        })
        if response.status_code not in [200, 204]:
            alert_status = f"Failed to send {alert_system_webhook} alert over Slack. Status code: {response.status_code}"
            new_entry = {
                "message": alert_status,
                "level": "error",
                "module": "slack_alerts",
            }
            log_exporter(new_entry)

            print(f"[!] {alert_status}")
            audit_trail_event(audit_trail, "ALERT_SYSTEM", {
            "status_code": response.status_code,
            "webhook": "slack",
            "message": "vulnerability severity report summary",
        })
            alerts_list.append(f"{alert_status}")
        else:
            alert_status = f"Alert sent {alert_system_webhook} alert over Slack. Status code: {response.status_code}"
            new_entry = {
                "message": alert_status,
                "level": "info",
                "module": "slack_alerts",
            }
            log_exporter(new_entry)

            print(f"[!] {alert_status}")
            audit_trail_event(audit_trail, "ALERT_SYSTEM", {
            "status_code": response.status_code,
            "webhook": "slack",
            "message": "vulnerability severity report summary",
        })
            alerts_list.append(f"{alert_status}")
    
    else:
        alert_status = f"Failed to send alert for {repo_name}. Alert webhook not set"
        new_entry = {
            "message": alert_status,
            "level": "error",
            "module": "alerts",
        }
        log_exporter(new_entry)
        
        audit_trail_event(audit_trail, "ALERT_SYSTEM", {
            "status": "fail",
            "webhook": "not found",
            "message": "vulnerability severity report summary",
        })
        alerts_list.append(f"{alert_status}")