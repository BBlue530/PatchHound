import json
from datetime import datetime
from logs.audit_trail import audit_trail_event
from utils.helpers import load_file_data, excluded_ids_list
from file_system.file_save import save_file

def generate_summary(audit_trail, repo_name, syft_sbom_path, grype_path, prio_path, semgrep_sast_report_path, trivy_report_path, exclusions_file_path, summary_report_path, tool_versions, rulesets):
    summary_dict = {}
    packages_dict = {}
    kev_prio_dict = {}
    exclusions_dict = {}

    rescan_timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")

    package_counter = 0

    kev_vuln_counter = 0
    excluded_kev_vuln_counter = 0

    excluded_vuln_counter = 0
    excluded_misconf_counter = 0
    excluded_exposed_secret_counter = 0

    vuln_counter = 0
    misconf_counter = 0
    exposed_secret_counter = 0

    syft_sbom_json = load_file_data(syft_sbom_path)
    grype_vulns_cyclonedx_json_data = load_file_data(grype_path)
    prio_vuln_data = load_file_data(prio_path)
    semgrep_sast_report_json = load_file_data(semgrep_sast_report_path)
    trivy_report_json = load_file_data(trivy_report_path)
    exclusions_file_json = load_file_data(exclusions_file_path)

    excluded_ids = excluded_ids_list(exclusions_file_json)

    def add_vuln(key, data):
        nonlocal excluded_vuln_counter, excluded_misconf_counter, excluded_exposed_secret_counter, vuln_counter, misconf_counter, exposed_secret_counter

        if key in excluded_ids:
            if key not in exclusions_dict:
                if data.get("source") in ("grype", "semgrep", "trivy_vulnerability"):
                    excluded_vuln_counter += 1
                    vuln_counter += 1
                elif data.get("source") == "trivy_misconfiguration":
                    excluded_misconf_counter += 1
                    misconf_counter += 1
                elif data.get("source") == "trivy_secret":
                    excluded_exposed_secret_counter += 1
                    exposed_secret_counter += 1
                exclusion_data = exclusion_lookup(exclusions_file_json, key, data)
                exclusions_dict[key] = exclusion_data

        else:
            if key not in summary_dict:
                if data.get("source") in ("grype", "semgrep", "trivy_vulnerability"):
                    vuln_counter += 1
                elif data.get("source") == "trivy_misconfiguration":
                    misconf_counter += 1
                elif data.get("source") == "trivy_secret":
                    exposed_secret_counter += 1
                summary_dict[key] = data

    def add_vuln_kev(key, data):
        nonlocal excluded_kev_vuln_counter, kev_vuln_counter

        if key in excluded_ids:
            if key not in exclusions_dict:
                excluded_kev_vuln_counter += 1
                kev_vuln_counter += 1

                exclusion_data = exclusion_lookup(exclusions_file_json, key, data)
                exclusions_dict[key] = exclusion_data

        else:
            if key not in kev_prio_dict:
                kev_vuln_counter += 1
                kev_prio_dict[key] = data
    
    if semgrep_sast_report_json.get("SAST_SCAN") is False:
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

    for comp in syft_sbom_json.get("components", []):
        name = comp.get("name")
        version = comp.get("version")
        if not name or not version:
            continue

        purl = comp.get("purl")
        cpe = comp.get("cpe")

        props = {p["name"]: p["value"] for p in comp.get("properties", []) if "name" in p and "value" in p}

        found_by = props.get("syft:package:foundBy")
        language = props.get("syft:package:language")
        package_type = props.get("syft:package:type")
        metadata_type = props.get("syft:package:metadataType")

        locations = [
            v for k, v in props.items()
            if k.startswith("syft:location") and k.endswith(":path")
        ]

        dedupe_key = f"{name}|{version}|{purl or cpe or ''}"

        if dedupe_key not in packages_dict:
            packages_dict[dedupe_key] = {
                "source": "syft",
                "id": comp.get("bom-ref"),
                "name": name,
                "version": version,
                "type": comp.get("type"),
                "purl": purl,
                "cpe": cpe,
                "package_type": package_type,
                "language": language,
                "metadata_type": metadata_type,
                "found_by": found_by,
                "locations": list(set(locations))
            }
            package_counter += 1
        else:
            packages_dict[dedupe_key]["locations"].extend(locations)
            packages_dict[dedupe_key]["locations"] = list(set(packages_dict[dedupe_key]["locations"]))

    for vuln in grype_vulns_cyclonedx_json_data.get("vulnerabilities", []):
        key = vuln.get("id")
        if not key:
            continue

        severity = None
        score = None
        vector = None

        for rating in vuln.get("ratings", []):

            if "CVSSv3" in (rating.get("method") or ""):
                severity = rating.get("severity") or severity
                score = rating.get("score")
                vector = rating.get("vector")
                break

            if severity is None and rating.get("severity"):
                severity = rating.get("severity")

            if score is None and rating.get("score") is not None:
                score = rating.get("score")

            if vector is None and rating.get("vector"):
                vector = rating.get("vector")

        try:
            score = float(score) if score is not None else None
        except (TypeError, ValueError):
            score = None

        pkg_ref = vuln.get("affects", [{}])[0].get("ref") or ""
        pkg_name, pkg_version = "unknown", "unknown"
        if pkg_ref.startswith("pkg:"):
            try:
                _, rest = pkg_ref.split("pkg:", 1)
                _, rest = rest.split("/", 1)
                pkg_name, pkg_version = rest.split("@", 1)
            except ValueError:
                pass

        link = get_vulnerability_link(key, vuln, "url")

        add_vuln(key, {
            "source": "grype",
            "id": key,
            "type": "vulnerability",
            "description": vuln.get("description")  or "No description available",
            "severity": severity,
            "score": score,
            "cvss_vector": vector,
            "package": pkg_name,
            "version": pkg_version,
            "link": link,
        })

    def prioritized_vulns_organizer(vuln, vuln_source):
        if not vuln:
            return
        
        key = vuln.get("cveID")
        if not key:
            return
        
        if key in exclusions_dict:
            target_dict = exclusions_dict
        elif key in summary_dict:
            target_dict = summary_dict
        else:
            target_dict = None

        if target_dict is not None:
            target_dict[key]["kev_priority"] = "CISA_KEV"
            target_dict[key]["kev_added_date"] = vuln.get("dateAdded")
            target_dict[key]["kev_due_date"] = vuln.get("dueDate")
        else:
            add_vuln_kev(key, {
                "source": "kev",
                "id": key,
                "vuln_source": vuln_source,
                "type": "kev",
                "description": vuln.get("shortDescription")  or "No description available",
                "severity": vuln.get("severity", "Unknown"),
                "link": "https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
                "kev_priority": "CISA_KEV",
                "title": vuln.get("vulnerabilityName") or "No title available",
                "vendor": vuln.get("vendorProject") or "No vendor available",
                "product": vuln.get("product") or "No product data available",
                "required_action": vuln.get("requiredAction") or "No required action available",
                "kev_added_date": vuln.get("dateAdded"),
                "kev_due_date": vuln.get("dueDate")
            })

    for vuln in prio_vuln_data.get("prioritized_vulns", {}).get("matched_grype_vulnerabilities", []):
        prioritized_vulns_organizer(vuln, "grype")

    for vuln in prio_vuln_data.get("prioritized_vulns", {}).get("matched_trivy_vulnerabilities", []):
        prioritized_vulns_organizer(vuln, "trivy")


    for issue in semgrep_sast_report_json.get("results", []):

        fingerprint = (
            issue.get("fingerprint")
            or issue.get("extra", {}).get("fingerprint")
            or "unknown_fingerprint"
        )
        unique_key = f"semgrep_{issue.get('check_id', 'unknown_rule')}_{fingerprint}"
        add_vuln(unique_key, {
            "source": "semgrep",
            "id": unique_key,
            "type": "vulnerability",
            "description": issue.get("extra", {}).get("message")  or "No description available",
            "severity": issue.get("extra", {}).get("severity", "Unknown"),
            "path": issue.get("path"),
            "line": issue.get("start", {}).get("line", "0")
        })

    for result in trivy_report_json.get("Results", []):
        for v in result.get("Vulnerabilities", []):

            score = None
            vector = None

            cvss = v.get("CVSS", {})

            if "nvd" in cvss:
                score = cvss["nvd"].get("V3Score") or cvss["nvd"].get("V2Score")
                vector = cvss["nvd"].get("V3Vector") or cvss["nvd"].get("V2Vector")
            elif "redhat" in cvss:
                score = cvss["redhat"].get("V3Score") or cvss["redhat"].get("V2Score")
                vector = cvss["redhat"].get("V3Vector") or cvss["redhat"].get("V2Vector")

            try:
                score = float(score) if score is not None else None
            except (TypeError, ValueError):
                score = None
            key = v.get("VulnerabilityID")
            if not key:
                continue

            link = get_vulnerability_link(key, v, "PrimaryURL")

            add_vuln(key, {
                "source": "trivy_vulnerability",
                "id": key,
                "type": "vuln",
                "description": v.get("Title") or v.get("Description") or "No description available",
                "severity": v.get("Severity"),
                "score": score,
                "cvss_vector": vector,
                "package": v.get("PkgName"),
                "version": v.get("InstalledVersion"),
                "link": link,
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
                "source": "trivy_misconfiguration",
                "id": key,
                "type": "misconfiguration",
                "description": m.get("Description") or "No description available",
                "severity": m.get("Severity"),
                "links": links,
                "title": m.get("Title") or "No title available",
                "resolution": m.get("Resolution") or "No fix guidance available",
                "file": m.get("Target")
            })

        for s in result.get("Secrets", []):
            key = s.get("RuleID")
            if not key:
                continue
            add_vuln(key, {
                "source": "trivy_secret",
                "id": key,
                "type": "secret",
                "description": s.get("Description") or "No description available",
                "severity": s.get("Severity", "HIGH"),
                "title": s.get("Title") or "No title available",
                "file": s.get("Target"),
                "message": s.get("Message"),
            })

    summary_report = {
        "rescan_timestamp": rescan_timestamp,
        "repo_name": repo_name,
        "packages": list(packages_dict.values()),
        "vulnerabilities": list(summary_dict.values()),
        "kev_vulnerabilities": list(kev_prio_dict.values()),
        "exclusions": list(exclusions_dict.values()),
        "counters": {
            "package_counter": package_counter,
            "kev_vuln_counter": kev_vuln_counter,
            "excluded_kev_vuln_counter": excluded_kev_vuln_counter,
            "excluded_vuln_counter": excluded_vuln_counter,
            "excluded_misconf_counter": excluded_misconf_counter,
            "excluded_exposed_secret_counter": excluded_exposed_secret_counter,
            "vuln_counter": vuln_counter,
            "misconf_counter": misconf_counter,
            "exposed_secret_counter": exposed_secret_counter
        },
        "tool_version": tool_versions,
#        {
#            "syft_version": tool_versions.get("syft_version"),
#            "semgrep_version": tool_versions.get("semgrep_version"),
#            "trivy_version": tool_versions.get("trivy_version"),
#            "grype_version": GRYPE_VERSION,
#            "cosign_version": COSIGN_VERSION,
#            "patchhound_version": patchhound_version
#        },
        "ruleset": rulesets,
#        {
#            "semgrep": semgrep_sast_ruleset
#        }
    }

    audit_trail_event(audit_trail, "SUMMARY_GENERATION", {
            "status": "success"
        })
    
    if summary_report:
        save_file(summary_report_path, summary_report)
    else:
        audit_trail_event(audit_trail, "FILE_SAVE", {
            "summary_report": summary_report_path,
            "status": "fail"
        })

    return excluded_vuln_counter, excluded_misconf_counter, excluded_exposed_secret_counter, vuln_counter, misconf_counter, exposed_secret_counter, excluded_kev_vuln_counter, kev_vuln_counter

def get_vulnerability_link(key, vuln, vuln_url_key):
    if key.startswith("GHSA"):
        link = f"https://github.com/advisories/{key}"
    elif key.startswith("CVE"):
        link = f"https://nvd.nist.gov/vuln/detail/{key}"
    elif key.startswith("PYSEC"):
        link = f"https://python-security.readthedocs.io/vuln/{key}"
    elif key.startswith("RUSTSEC"):
        link = f"https://rustsec.org/advisories/{key}.html"
    elif key.startswith("OSV"):
        link = f"https://osv.dev/vulnerability/{key}"
    elif key.startswith("GO"):
        link = f"https://pkg.go.dev/vuln/{key}"
    else:
        link = vuln.get("references", [{}])[0].get(f"{vuln_url_key}", "No link available")
    return link

def exclusion_lookup(exclusions_file_json, key, data):
    for e in exclusions_file_json.get("exclusions", []):
        if e.get("vulnerability_id") == key:
            data["scope"] = e.get("scope")
            data["public_comment"] = e.get("public_comment")
            data["private_comment"] = e.get("private_comment")
            return data
    return data

def update_summary_rescan(all_new_cves, not_excluded_all_new_cves, all_new_kev_cves, not_excluded_all_new_kev_cves, grype_vulns_cyclonedx_json_data, current_prio_vuln_data, summary_report_path):
    new_not_excluded_vulns_counter = 0
    new_excluded_vulns_counter = 0

    new_not_excluded_kev_vulns_counter = 0
    new_excluded_kev_vulns_counter = 0
    
    new_not_excluded_vulns = []
    new_excluded_vulns = []

    new_not_excluded_kev_vulns = []
    new_excluded_kev_vulns = []

    rescan_timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")

    excluded_all_new_cves = all_new_cves - not_excluded_all_new_cves
    excluded_all_new_kev_cves = all_new_kev_cves - not_excluded_all_new_kev_cves


    # This part will handle all new not excluded CVEs found
    for vuln in grype_vulns_cyclonedx_json_data.get("vulnerabilities", []):
        key = vuln.get("id")
        if not key:
            continue
        elif key not in all_new_cves:
            continue

        severity = None
        score = None
        vector = None

        for rating in vuln.get("ratings", []):
                
            if "CVSSv3" in (rating.get("method") or ""):
                severity = rating.get("severity") or severity
                score = rating.get("score")
                vector = rating.get("vector")
                break

            if severity is None and rating.get("severity"):
                severity = rating.get("severity")

            if score is None and rating.get("score") is not None:
                score = rating.get("score")

            if vector is None and rating.get("vector"):
                vector = rating.get("vector")

        try:
            score = float(score) if score is not None else None
        except (TypeError, ValueError):
            score = None

        pkg_ref = vuln.get("affects", [{}])[0].get("ref") or ""
        pkg_name, pkg_version = "unknown", "unknown"
        if pkg_ref.startswith("pkg:"):
            try:
                _, rest = pkg_ref.split("pkg:", 1)
                _, rest = rest.split("/", 1)
                pkg_name, pkg_version = rest.split("@", 1)
            except ValueError:
                pass

        link = get_vulnerability_link(key, vuln, "url")

        if key in not_excluded_all_new_cves:
            new_not_excluded_vulns.append({
                "source": "grype",
                "id": key,
                "type": "vulnerability",
                "description": vuln.get("description")  or "No description available",
                "severity": severity,
                "score": score,
                "cvss_vector": vector,
                "package": pkg_name,
                "version": pkg_version,
                "link": link,
                "vuln_found_timestamp": rescan_timestamp
            })
            new_not_excluded_vulns_counter += 1

        elif key in excluded_all_new_cves:
            new_excluded_vulns.append({
                "source": "grype",
                "id": key,
                "type": "vulnerability",
                "description": vuln.get("description")  or "No description available",
                "severity": severity,
                "score": score,
                "cvss_vector": vector,
                "package": pkg_name,
                "version": pkg_version,
                "link": link,
                "vuln_found_timestamp": rescan_timestamp
            })
            new_excluded_vulns_counter += 1
        
        if key in not_excluded_all_new_kev_cves:
            new_not_excluded_kev_vulns.append({
                "source": "grype",
                "id": key,
                "type": "vulnerability",
                "description": vuln.get("description")  or "No description available",
                "severity": severity,
                "score": score,
                "cvss_vector": vector,
                "package": pkg_name,
                "version": pkg_version,
                "link": link,
                "vuln_found_timestamp": rescan_timestamp
            })
            new_not_excluded_kev_vulns_counter += 1

        elif key in excluded_all_new_kev_cves:
            new_excluded_kev_vulns.append({
                "source": "grype",
                "id": key,
                "type": "vulnerability",
                "description": vuln.get("description")  or "No description available",
                "severity": severity,
                "score": score,
                "cvss_vector": vector,
                "package": pkg_name,
                "version": pkg_version,
                "link": link,
                "vuln_found_timestamp": rescan_timestamp
            })
            new_excluded_kev_vulns_counter += 1

    summary_report_json = load_file_data(summary_report_path)
    
    # Normal vulns
    append_json_data(summary_report_json, "new_vulnerabilities", list(new_not_excluded_vulns))
    append_json_data(summary_report_json, "counters.new_vulnerabilities_counter", new_not_excluded_vulns_counter)

    append_json_data(summary_report_json, "new_excluded_vulnerabilities", list(new_excluded_vulns))
    append_json_data(summary_report_json, "counters.new_excluded_vulnerabilities_counter", new_excluded_vulns_counter)
    
    # Kev vulns
    append_json_data(summary_report_json, "new_kev_vulnerabilities", list(not_excluded_all_new_kev_cves))
    append_json_data(summary_report_json, "counters.new_kev_vulnerabilities_counter", new_not_excluded_kev_vulns_counter)

    append_json_data(summary_report_json, "new_excluded_kev_vulnerabilities", list(new_excluded_kev_vulns))
    append_json_data(summary_report_json, "counters.new_excluded_kev_vulnerabilities_counter", new_excluded_kev_vulns_counter)

    summary_report_json["rescan_timestamp"] = rescan_timestamp

    with open(summary_report_path, "w") as f:
        json.dump(summary_report_json, f, indent=2)

def append_json_data(json_data, json_nest, new_entry_json_data):
    json_keys = json_nest.split(".")
    current_json = json_data

    for json_key in json_keys[:-1]:
        if json_key not in current_json or not isinstance(current_json[json_key], dict):
            current_json[json_key] = {}
        current_json = current_json[json_key]

    final_json_key = json_keys[-1]

    # Counter will get the new value added on top of the existing one
    if isinstance(new_entry_json_data, int):
        existing_value = current_json.get(final_json_key)

        if existing_value is None:
            current_json[final_json_key] = new_entry_json_data
        elif isinstance(existing_value, int):
            current_json[final_json_key] += new_entry_json_data
        else:
            raise TypeError(f"[!] Cannot add '{json_nest}': existing value is not int")
        return

    # This will append the new entry
    if isinstance(new_entry_json_data, list):
        current_json.setdefault(final_json_key, [])
        if not isinstance(current_json[final_json_key], list):
            raise TypeError(f"[!] Cannot append '{json_nest}': existing value is not list")
        current_json[final_json_key].extend(new_entry_json_data)
        return

    # Replacement fallback
    current_json[final_json_key] = new_entry_json_data