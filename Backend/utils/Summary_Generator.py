def generate_summary(vulns_cyclonedx_json, prio_vuln_data, sast_report_json, trivy_report_json):

    summary_dict = {}

    for vuln in vulns_cyclonedx_json.get("vulnerabilities", []):
        key = vuln.get("id")
        summary_dict[key] = {
            "source": "grype",
            "severity": vuln.get("severity"),
            "package": vuln.get("packageName"),
            "version": vuln.get("version"),
            "description": vuln.get("description"),
            }

    for vuln in prio_vuln_data.get("prioritized_vulns", []):
        key = vuln.get("id")
        if key in summary_dict:
            summary_dict[key]["kev_priority"] = vuln.get("priority")
        else:
            summary_dict[key] = {
                "source": "kev",
                "kev_priority": vuln.get("priority"),
                "severity": vuln.get("severity", "Unknown"),
                }

    for issue in sast_report_json.get("results", []):
        key = f"{issue['path']}:{issue['start']}_{issue['rule_id']}"
        summary_dict[key] = {
            "source": "sast",
            "rule_id": issue.get("rule_id"),
            "path": issue.get("path"),
            "line": issue.get("start"),
            "message": issue.get("message"),
            "severity": issue.get("severity", "Unknown"),
            }

    for vuln in trivy_report_json.get("Results", []):
        for v in vuln.get("Vulnerabilities", []):
            key = v.get("VulnerabilityID")
            summary_dict[key] = {
                "source": "trivy",
                "type": "vuln",
                "package": v.get("PkgName"),
                "version": v.get("InstalledVersion"),
                "severity": v.get("Severity"),
                "title": v.get("Title"),
                }
    
    for vuln in trivy_report_json.get("Results", []):
        for m in vuln.get("Misconfigurations", []):
            key = m.get("ID")
            summary_dict[key] = {
                "source": "trivy",
                "type": "misconfiguration",
                "title": m.get("Title"),
                "description": m.get("Description"),
                "severity": m.get("Severity"),
                "message": m.get("Message"),
                "file": m.get("File"),
                }
    
    for vuln in trivy_report_json.get("Results", []):
        for s in vuln.get("Secrets", []):
            key = s.get("RuleID")
            summary_dict[key] = {
                "source": "trivy",
                "type": "secret",
                "title": s.get("Title"),
                "description": s.get("Description"),
                "severity": "HIGH",
                "message": s.get("Message"),
                "file": s.get("File"),
                }

    summary_report = list(summary_dict.values())
    return summary_report