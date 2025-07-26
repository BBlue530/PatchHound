def extract_cve_ids(vuln_data):
    return set(vuln.get("id") for vuln in vuln_data.get("vulnerabilities", []) if vuln.get("id"))