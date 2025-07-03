import os
import json
from datetime import datetime

def save_scan_files(current_repo, sbom_file, vulns_cyclonedx_json, prio_vuln_data):
    
    safe_repo_name = current_repo.replace("/", "_")
    
    timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    scan_dir = os.path.join(safe_repo_name, timestamp)
    
    os.makedirs(scan_dir, exist_ok=True)

    sbom_path = os.path.join(scan_dir, f"{safe_repo_name}_sbom_cyclonedx.json")
    if hasattr(sbom_file, 'read'):
        sbom_file.seek(0)
        with open(sbom_path, "w") as f:
            json.dump(json.load(sbom_file), f, indent=4)
    else:
        with open(sbom_path, "w") as f:
            json.dump(sbom_file, f, indent=4)

    grype_path = os.path.join(scan_dir, f"{safe_repo_name}_vulns_cyclonedx.json")
    with open(grype_path, "w") as f:
        json.dump(vulns_cyclonedx_json, f, indent=4)

    prio_path = os.path.join(scan_dir, f"{safe_repo_name}_prio_vuln_data.json")
    with open(prio_path, "w") as f:
        json.dump(prio_vuln_data, f, indent=4)