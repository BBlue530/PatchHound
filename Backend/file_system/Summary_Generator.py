def generate_summary(vulns_cyclonedx_json, prio_vuln_data, sast_report_json, trivy_report_json, exclusions_file_json):

    summary_dict = {}
    exclusions_dict = {}

    excluded_ids = {
        e.get("vulnerability")
        for e in exclusions_file_json.get("exclusions", [])
        if e.get("vulnerability")
    }

    def add_vuln(key, data):
        if key in excluded_ids:
            exclusions_dict[key] = data
        else:
            summary_dict[key] = data
    
    if sast_report_json.get("SAST_SCAN") is False:
        summary_dict["SAST_SCAN_SKIPPED"] = {
            "source": "semgrep",
            "status": "scan skipped",
            "reason": "SAST_SCAN=false"
        }
    if trivy_report_json.get("TRIVY_SCAN") is False:
        summary_dict["TRIVY_SCAN_SKIPPED"] = {
            "source": "trivy",
            "status": "scan skipped",
            "reason": "TRIVY_SCAN=false"
        }

    for vuln in vulns_cyclonedx_json.get("vulnerabilities", []):
        key = vuln.get("id")
        vuln_id = key or ""
        if vuln_id.startswith("GHSA"):
            link = f"https://github.com/advisories/{vuln_id}"
        elif vuln_id.startswith("CVE"):
            link = f"https://cve.mitre.org/cgi-bin/cvename.cgi?name={vuln_id}"
        else:
            link = vuln.get("references", [{}])[0].get("url", "No link available")

        add_vuln(key, {
            "source": "grype",
            "id": key,
            "severity": vuln.get("severity"),
            "package": vuln.get("packageName"),
            "version": vuln.get("version"),
            "description": vuln.get("description"),
            "link": link,
        })

    for vuln in prio_vuln_data.get("prioritized_vulns", []):
        key = vuln.get("id")
        target_dict = summary_dict if key in summary_dict else exclusions_dict
        if key in summary_dict or key in exclusions_dict:
            target_dict[key]["kev_priority"] = vuln.get("priority")
        else:
            add_vuln(key, {
                "source": "kev",
                "id": key,
                "kev_priority": vuln.get("priority"),
                "severity": vuln.get("severity", "Unknown"),
            })

    for issue in sast_report_json.get("results", []):
        rule_id = issue.get("rule_id", "unknown_rule")
        start_line = issue.get("start", "0")
        path = issue.get("path", "unknown_path")
        key = f"{path}:{start_line}_{rule_id}"
        add_vuln(key, {
            "source": "semgrep",
            "rule_id": rule_id,
            "path": path,
            "line": start_line,
            "message": issue.get("message", ""),
            "severity": issue.get("severity", "Unknown"),
        })

    for result in trivy_report_json.get("Results", []):
        for v in result.get("Vulnerabilities", []):
            key = v.get("VulnerabilityID")
            add_vuln(key, {
                "source": "trivy",
                "id": key,
                "type": "vuln",
                "package": v.get("PkgName"),
                "version": v.get("InstalledVersion"),
                "severity": v.get("Severity"),
                "title": v.get("Title"),
                "link": v.get("PrimaryURL", "No link available"),
            })

        for m in result.get("Misconfigurations", []):
            key = m.get("ID")
            add_vuln(key, {
                "source": "trivy",
                "id": key,
                "type": "misconfiguration",
                "title": m.get("Title"),
                "description": m.get("Description"),
                "severity": m.get("Severity"),
                "message": m.get("Message"),
                "file": m.get("File"),
                "link": m.get("PrimaryURL", "No link available"),
            })

        for s in result.get("Secrets", []):
            key = s.get("RuleID")
            add_vuln(key, {
                "source": "trivy",
                "id": key,
                "type": "secret",
                "title": s.get("Title"),
                "description": s.get("Description"),
                "severity": "HIGH",
                "message": s.get("Message"),
                "file": s.get("File"),
            })

    summary_report = {
        "vulnerabilities": list(summary_dict.values()),
        "exclusions": list(exclusions_dict.values())
    }

    return summary_report