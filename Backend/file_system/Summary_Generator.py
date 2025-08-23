def generate_summary(vulns_cyclonedx_json, prio_vuln_data, sast_report_json, trivy_report_json, exclusions_file_json):
    summary_dict = {}
    kev_prio_dict = {}
    exclusions_dict = {}

    excluded_ids = {
        e.get("vulnerability")
        for e in exclusions_file_json.get("exclusions", [])
        if e.get("vulnerability")
    }

    exclusion_comments = {
    e.get("vulnerability"): e.get("comment", "")
    for e in exclusions_file_json.get("exclusions", [])
    if e.get("vulnerability")
    }

    def add_vuln(key, data):
        if key in excluded_ids:
            data["comment"] = exclusion_comments.get(key, "")
            exclusions_dict[key] = data
        else:
            summary_dict[key] = data

    def add_vuln_kev(key, data):
        if key in excluded_ids:
            data["comment"] = exclusion_comments.get(key, "")
            exclusions_dict[key] = data
        else:
            kev_prio_dict[key] = data
    
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
        if not key:
            continue

        severity = None
        for rating in vuln.get("ratings", []):
            if rating.get("severity"):
                severity = rating["severity"]
                break

        pkg_ref = vuln.get("affects", [{}])[0].get("ref") or ""
        pkg_name, pkg_version = "unknown", "unknown"
        if pkg_ref.startswith("pkg:"):
            try:
                _, rest = pkg_ref.split("pkg:", 1)
                _, rest = rest.split("/", 1)
                pkg_name, pkg_version = rest.split("@", 1)
            except ValueError:
                pass

        if key.startswith("GHSA"):
            link = f"https://github.com/advisories/{key}"
        elif key.startswith("CVE"):
            link = f"https://cve.mitre.org/cgi-bin/cvename.cgi?name={key}"
        else:
            link = vuln.get("references", [{}])[0].get("url", "No link available")

        add_vuln(key, {
            "source": "grype",
            "id": key,
            "severity": severity,
            "package": pkg_name,
            "version": pkg_version,
            "description": vuln.get("description", "No description available"),
            "link": link,
        })

    for vuln in prio_vuln_data.get("prioritized_vulns", []):
        key = vuln.get("cveID")
        if not key:
            continue

        target_dict = summary_dict if key in summary_dict else exclusions_dict

        if key in target_dict:
            target_dict[key]["kev_priority"] = "CISA_KEV"
            target_dict[key]["kev_added_date"] = vuln.get("dateAdded")
            target_dict[key]["kev_due_date"] = vuln.get("dueDate")
        else:
            add_vuln_kev(key, {
                "source": "kev",
                "id": key,
                "kev_priority": "CISA_KEV",
                "severity": vuln.get("severity", "Unknown"),
                "description": vuln.get("shortDescription", ""),
                "title": vuln.get("vulnerabilityName", ""),
                "vendor": vuln.get("vendorProject", ""),
                "product": vuln.get("product", ""),
                "required_action": vuln.get("requiredAction", ""),
                "kev_added_date": vuln.get("dateAdded"),
                "kev_due_date": vuln.get("dueDate"),
                "link": "https://www.cisa.gov/known-exploited-vulnerabilities-catalog"
            })

    for issue in sast_report_json.get("results", []):
        rule_id = issue.get("check_id", "unknown_rule")
        severity = issue.get("extra", {}).get("severity", "Unknown")
        message = issue.get("extra", {}).get("message", "")
        path = issue.get("path", "unknown_path")
        line = issue.get("start", {}).get("line", "0")

        key = rule_id
        add_vuln(key, {
            "source": "semgrep",
            "id": rule_id,
            "path": path,
            "line": line,
            "message": message,
            "severity": severity,
        })

    for result in trivy_report_json.get("Results", []):
        for v in result.get("Vulnerabilities", []):
            key = v.get("VulnerabilityID")
            if not key:
                continue
            add_vuln(key, {
                "source": "trivy",
                "id": key,
                "type": "vuln",
                "package": v.get("PkgName"),
                "version": v.get("InstalledVersion"),
                "severity": v.get("Severity"),
                "title": v.get("Title") or v.get("Description") or "No description available",
                "link": v.get("PrimaryURL", "No link available"),
            })

        for m in result.get("Misconfigurations", []):
            key = m.get("ID")
            if not key:
                continue
            refs = m.get("References", [])
            links = []
            for r in refs:
                if isinstance(r, dict) and r.get("url"):
                    links.append(r["url"])
                elif isinstance(r, str):
                    links.append(r)
            add_vuln(key, {
                "source": "trivy",
                "id": key,
                "type": "misconfiguration",
                "title": m.get("Title") or m.get("Description") or "No description",
                "description": m.get("Description"),
                "resolution": m.get("Resolution", "No fix guidance"),
                "severity": m.get("Severity"),
                "file": m.get("Target"),
                "links": links
            })

        for s in result.get("Secrets", []):
            key = s.get("RuleID")
            if not key:
                continue
            add_vuln(key, {
                "source": "trivy",
                "id": key,
                "type": "secret",
                "title": s.get("Title") or "No title",
                "description": s.get("Description"),
                "severity": s.get("Severity", "HIGH"),
                "file": s.get("Target"),
                "message": s.get("Message"),
            })

    summary_report = {
        "vulnerabilities": list(summary_dict.values()),
        "kev_vulnerabilities": list(kev_prio_dict.values()),
        "exclusions": list(exclusions_dict.values())
    }

    return summary_report