from utils.helpers import load_file_data
from logs.event_handler import event
from core.variables import kev_catalog, log_type_info, log_type_debug, log_type_error, log_message_key, log_level_key, log_module_key, log_details_key

def compare_kev_catalog(audit_trail, grype_vulns_cyclonedx_json_data, trivy_report_data):
    kev_data = load_file_data(kev_catalog)

    kev_version = kev_data["catalogVersion"]
    kev_release_date = kev_data["dateReleased"]

    grype_cyclone_ids = set(vuln["id"] for vuln in grype_vulns_cyclonedx_json_data.get("vulnerabilities", []))

    grype_matched_vulns = []
    for vuln in kev_data.get("vulnerabilities", []):
        if vuln["cveID"] in grype_cyclone_ids:
            grype_matched_vulns.append(vuln)

    trivy_cyclone_ids = set()

    for result in trivy_report_data.get("Results", []):
        for vuln in result.get("Vulnerabilities", []) or []:
            if vuln.get("VulnerabilityID"):
                trivy_cyclone_ids.add(vuln["VulnerabilityID"])

    trivy_matched_vulns = []
    for vuln in kev_data.get("vulnerabilities", []):
        if vuln["cveID"] in trivy_cyclone_ids:
            trivy_matched_vulns.append(vuln)
    
    if grype_matched_vulns or trivy_matched_vulns:
        event(audit_trail, {
            log_message_key: "vulnerabilities found in kev catalog",
            log_level_key: log_type_info,
            log_module_key: "compare_kev_catalog",
            log_details_key: {
                "kev_version": kev_version,
                "kev_release_date": kev_release_date,
                "matched_grype_vulnerabilities": grype_matched_vulns,
                "matched_trivy_vulnerabilities": trivy_matched_vulns
            }
        })

    prio_vuln_data = {
        "version": kev_version,
        "release_date": kev_release_date,
        "prioritized_vulns": {
            "matched_grype_vulnerabilities": grype_matched_vulns,
            "matched_trivy_vulnerabilities": trivy_matched_vulns
        }
    }
    
    return prio_vuln_data