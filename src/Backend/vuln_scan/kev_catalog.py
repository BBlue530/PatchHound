import json
from logs.audit_trail import audit_trail_event
from core.variables import kev_catalog

def compare_kev_catalog(audit_trail, grype_vulns_cyclonedx_json_data):
    with open(kev_catalog, "r") as f:
        kev_data = json.load(f)

    kev_version = kev_data["catalogVersion"]
    kev_release_date = kev_data["dateReleased"]

    cyclone_ids = set(vuln["id"] for vuln in grype_vulns_cyclonedx_json_data.get("vulnerabilities", []))

    matched_vulns = []
    for vuln in kev_data.get("vulnerabilities", []):
        if vuln["cveID"] in cyclone_ids:
            matched_vulns.append(vuln)
    
    if matched_vulns:
        audit_trail_event(audit_trail, "KEV_CATALOG", {
                "kev_version": kev_version,
                "kev_release_date": kev_release_date,
                "matched_vulnerabilities": matched_vulns
            })

    prio_vuln_data = {
        "version": kev_version,
        "release_date": kev_release_date,
        "prioritized_vulns": matched_vulns
    }
    
    return prio_vuln_data