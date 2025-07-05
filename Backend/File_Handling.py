import os
import json
from datetime import datetime
import subprocess
from Variables import all_repo_scans_folder
from Kev_Catalog import compare_kev_catalog

def save_scan_files(current_repo, sbom_file, vulns_cyclonedx_json, prio_vuln_data, license_key):
        
    safe_repo_name = current_repo.replace("/", "_")
    timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    scan_dir = os.path.join(all_repo_scans_folder, license_key, safe_repo_name, timestamp)
    
    os.makedirs(scan_dir, exist_ok=True)

    sbom_path = os.path.join(scan_dir, f"{safe_repo_name}_sbom_cyclonedx.json")
    if hasattr(sbom_file, 'read'):
        sbom_file.seek(0)
        with open(sbom_path, "w") as f:
            json.dump(json.load(sbom_file), f, indent=4)
    else:
        with open(sbom_path, "w") as f:
            json.dump(sbom_file, f, indent=4)
    
    sbom_sig_path = f"{sbom_path}.sig"
    try:
        subprocess.run(
            ["cosign", "sign-blob", "--key", "cosign.key", "--output-signature", sbom_sig_path, sbom_path],
            check=True
        )
        print(f"[+] SBOM signed: {sbom_sig_path}")
    except subprocess.CalledProcessError as e:
        print(f"[!] Failed to sign SBOM: {e.stderr}")

    grype_path = os.path.join(scan_dir, f"{safe_repo_name}_vulns_cyclonedx.json")
    with open(grype_path, "w") as f:
        json.dump(vulns_cyclonedx_json, f, indent=4)

    prio_path = os.path.join(scan_dir, f"{safe_repo_name}_prio_vuln_data.json")
    with open(prio_path, "w") as f:
        json.dump(prio_vuln_data, f, indent=4)

def scan_latest_sboms():

    if not os.path.isdir(all_repo_scans_folder):
        print(f"[~] Creating missing scans folder: {all_repo_scans_folder}")
        os.makedirs(all_repo_scans_folder, exist_ok=True)
        
    for license_key in os.listdir(all_repo_scans_folder):
        license_path = os.path.join(all_repo_scans_folder, license_key)
        if not os.path.isdir(license_path):
            continue
        print(f"[~] Scanning for license key: {license_key}")

        for repo_name in os.listdir(license_path):
            repo_path = os.path.join(license_path, repo_name)
            if not os.path.isdir(repo_path):
                continue

            # Get all timestamp folders inside the repo folder
            timestamp_folders = sorted([f for f in os.listdir(repo_path) if os.path.isdir(os.path.join(repo_path, f))],reverse=True)  # Latest is the first since timestamp sort themself

            if not timestamp_folders:
                print(f"[!] No scans found for repo: {repo_name}")
                continue

            latest_scan_dir = os.path.join(repo_path, timestamp_folders[0])
            sbom_path = os.path.join(latest_scan_dir, f"{repo_name}_sbom_cyclonedx.json")
            sbom_sig_path = f"{sbom_path}.sig"

            if not os.path.exists(sbom_path):
                print(f"[!] SBOM not found for repo: {repo_name}")
                continue

            if not os.path.exists(sbom_sig_path):
                print(f"[!] Signature missing for SBOM in repo: {repo_name}")
                continue

            try:
                subprocess.run(
                    ["cosign", "verify-blob", "--key", "cosign.pub", "--signature", sbom_sig_path, sbom_path],
                    check=True
                )
                print(f"[+] Verified SBOM signature for repo: {repo_name}")
            except subprocess.CalledProcessError:
                print(f"[!] Signature failed for repo: {repo_name}!")
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

                vulns_cyclonedx_json_data = json.loads(vulns_cyclonedx_json.stdout)

                # Save the scan output
                with open(vulns_output_path, "w") as f:
                    f.write(vulns_cyclonedx_json.stdout)

                prio_vuln_data = compare_kev_catalog(vulns_cyclonedx_json_data)
                prio_path = os.path.join(latest_scan_dir, f"{repo_name}_prio_vuln_data.json")
                with open(prio_path, "w") as f:
                    json.dump(prio_vuln_data, f, indent=4)

                print(f"[+] Scan finished for repo: {repo_name}")

            except subprocess.CalledProcessError as e:
                print(f"[!] Scan failed for {repo_name}: {e.stderr}")