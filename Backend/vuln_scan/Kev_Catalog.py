import json
from core.variables import kev_catalog

def compare_kev_catalog(cyclonedx_data):
    with open(kev_catalog, "r") as f:
        kev_data = json.load(f)

    kev_version = kev_data["catalogVersion"]
    kev_release_date = kev_data["dateReleased"]

    cyclone_ids = set(vuln["id"] for vuln in cyclonedx_data.get("vulnerabilities", []))

    matched_vulns = []
    for vuln in kev_data.get("vulnerabilities", []):
        if vuln["cveID"] in cyclone_ids:
            matched_vulns.append(vuln)

    prio_vuln_data = {
        "version": kev_version,
        "release_date": kev_release_date,
        "prioritized_vulns": matched_vulns
    }
    
    return prio_vuln_data