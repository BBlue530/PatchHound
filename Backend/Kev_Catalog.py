import json
from Variables import kev_catalog

def compare_kev_catalog(vulns_cyclonedx_json):
    with open(kev_catalog, "r") as f:
        kev_data = json.load(f)

    kev_version = kev_data["catalogVersion"]
    kev_release_date = kev_data["dateReleased"]

    with open(vulns_cyclonedx_json, "r") as f:
        cyclonedx_data = json.load(f)

    cyclone_ids = set(vuln["id"] for vuln in cyclonedx_data.get("vulnerabilities", []))

    matched_vulns = []
    for vuln in kev_data.get("vulnerabilities", []):
        if vuln["cveID"] in cyclone_ids:
            matched_vulns.append(vuln)

    prio_vuln_data = {
        "version": kev_version,
        "release_date": kev_release_date,
        "prioritized_vulnerabilities": matched_vulns
    }
    
    return prio_vuln_data