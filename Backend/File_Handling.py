import os
import json
from datetime import datetime
import subprocess
from Variables import all_repo_scans_folder
from Kev_Catalog import compare_kev_catalog

def save_scan_files(current_repo, sbom_file, vulns_cyclonedx_json, prio_vuln_data):

    if not os.path.isdir(all_repo_scans_folder):
        print(f"[~] Creating missing scans folder: {all_repo_scans_folder}")
        os.makedirs(all_repo_scans_folder, exist_ok=True)
        
    safe_repo_name = current_repo.replace("/", "_")
    timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    scan_dir = os.path.join(all_repo_scans_folder, safe_repo_name, timestamp)
    
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

def scan_latest_sboms():

    for repo_name in os.listdir(all_repo_scans_folder):
        repo_path = os.path.join(all_repo_scans_folder, repo_name)
        if not os.path.isdir(repo_path):
            continue

        # Get all timestamp folders inside the repo folder
        timestamp_folders = sorted([f for f in os.listdir(repo_path) if os.path.isdir(os.path.join(repo_path, f))],reverse=True)  # Latest is the first since timestamp sort themself

        if not timestamp_folders:
            print(f"[!] No scans found for repo: {repo_name}")
            continue

        latest_scan_dir = os.path.join(repo_path, timestamp_folders[0])
        sbom_path = os.path.join(latest_scan_dir, f"{repo_name}_sbom_cyclonedx.json")

        if not os.path.exists(sbom_path):
            print(f"[!] SBOM not found for repo: {repo_name}")
            continue

        print(f"[~] Scanning latest SBOM for repo: {repo_name}")
        try:
            # Run Grype and save result into file inside latest_scan_dir
            vulns_output_path = os.path.join(latest_scan_dir, f"{repo_name}_vulns_cyclonedx.json")
            vulns_cyclonedx_json = subprocess.run(
                ["grype", sbom_path, "-o", "cyclonedx-json"],
                capture_output=True,
                text=True,
                check=True
            )

            # Save the scan output
            with open(vulns_output_path, "w") as f:
                f.write(vulns_cyclonedx_json.stdout)

            prio_vuln_data = compare_kev_catalog(vulns_output_path)
            prio_path = os.path.join(latest_scan_dir, f"{repo_name}_prio_vuln_data.json")
            with open(prio_path, "w") as f:
                json.dump(prio_vuln_data, f, indent=4)

        except subprocess.CalledProcessError as e:
            print(f"[!] Scan failed for {repo_name}: {e.stderr}")