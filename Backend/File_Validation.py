import os
import json
from datetime import datetime
import subprocess
from Variables import all_repo_scans_folder, scheduled_event_commit_sha, scheduled_event_commit_author, local_bin, env
from Kev_Catalog import compare_kev_catalog
from Alerts import alert_event_system
from Log import log_event
from Helpers import extract_cve_ids

def sbom_validation():

    env["PATH"] = local_bin + os.pathsep + env.get("PATH", "")

    if not os.path.isdir(all_repo_scans_folder):
        print(f"[~] Creating missing scans folder: {all_repo_scans_folder}")
        os.makedirs(all_repo_scans_folder, exist_ok=True)
    
    # List all directories inside all_repo_scans_folder aka the license keys
    for license_key in os.listdir(all_repo_scans_folder):
        license_path = os.path.join(all_repo_scans_folder, license_key)
        if not os.path.isdir(license_path):
            continue
        print(f"[~] Scanning for license key: {license_key}")

        # List all directories inside the license key dir which will be the repo_name
        for repo_name in os.listdir(license_path):
            repo_path = os.path.join(license_path, repo_name)
            if not os.path.isdir(repo_path):
                continue

            # List all directories inside the repo_name dir and sort them.
            # Latest is the first since timestamp sort themself
            timestamp_folders = sorted([f for f in os.listdir(repo_path) if os.path.isdir(os.path.join(repo_path, f))],reverse=True)

            if not timestamp_folders:
                print(f"[!] No scans found for repo: {repo_name}")
                continue
            
            # Create the full path for the latest scan inside the repo
            # all_repo_scans_folder, license_key, repo_name, timestamp_folders, {repo_name}_sbom_cyclonedx.json
            latest_scan_dir = os.path.join(repo_path, timestamp_folders[0])

            sbom_path = os.path.join(latest_scan_dir, f"{repo_name}_sbom_cyclonedx.json")
            alert_path = os.path.join(repo_path, f"{repo_name}_alert.json")
            att_sig_path = f"{sbom_path}_att.sig"
            sbom_att_path = f"{sbom_path}.att"
            cosign_pub_path = os.path.join(latest_scan_dir, f"{repo_name}.pub")

            vulns_output_path = os.path.join(latest_scan_dir, f"{repo_name}_vulns_cyclonedx.json")
            prio_output_path = os.path.join(latest_scan_dir, f"{repo_name}_prio_vuln_data.json")

            if not os.path.exists(sbom_path):
                message = f"[!] SBOM missing for repo: {repo_name}"
                alert = "Scheduled Event : SBOM Missing"
                timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
                print(f"{message}")
                alert_event_system(message, alert, alert_path)
                log_event(repo_path, repo_name, timestamp, message, scheduled_event_commit_sha, scheduled_event_commit_author)
                continue

            if not os.path.exists(sbom_att_path):
                message = f"[!] Attestation missing for SBOM in repo: {repo_name}"
                alert = "Scheduled Event : Attestation Missing"
                timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
                print(f"{message}")
                alert_event_system(message, alert, alert_path)
                log_event(repo_path, repo_name, timestamp, message, scheduled_event_commit_sha, scheduled_event_commit_author)
                continue

            if not os.path.exists(att_sig_path):
                message = f"[!] Signature missing for Attestation in repo: {repo_name}"
                alert = "Scheduled Event : Signature Missing"
                timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
                print(f"{message}")
                alert_event_system(message, alert, alert_path)
                log_event(repo_path, repo_name, timestamp, message, scheduled_event_commit_sha, scheduled_event_commit_author)
                continue
            
            try:
                subprocess.run(
                    [
                        "cosign", "verify-blob-attestation",
                        "--key", cosign_pub_path,
                        "--signature", sbom_att_path,
                        "--type", "cyclonedx",
                        sbom_path
                    ],
                    check=True,
                    env=env
                )
                print(f"[+] Verified SBOM attestation for repo: {repo_name}")
            except subprocess.CalledProcessError:
                message = f"[!] Attestation verification failed for repo: {repo_name}!"
                alert = "Scheduled Event : Attestation Fail"
                timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
                print(f"{message}")
                alert_event_system(message, alert, alert_path)
                log_event(repo_path, repo_name, timestamp, message, scheduled_event_commit_sha, scheduled_event_commit_author)
                continue

            try:
                subprocess.run(
                    [
                        "cosign", "verify-blob",
                        "--key", cosign_pub_path,
                        "--signature", att_sig_path,
                        sbom_att_path
                    ],
                    check=True,
                    env=env
                )
                print(f"[+] Verified Attestation signature for repo: {repo_name}")
            except subprocess.CalledProcessError:
                message = f"[!] Signature for Attestation failed for repo: {repo_name}!"
                alert = "Scheduled Event : Signature Fail"
                timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
                print(f"{message}")
                alert_event_system(message, alert, alert_path)
                log_event(repo_path, repo_name, timestamp, message, scheduled_event_commit_sha, scheduled_event_commit_author)
                continue

            print(f"[~] Scanning latest SBOM for repo: {repo_name}")
            try:
                vulns_cyclonedx_json = subprocess.run(
                    ["grype", sbom_path, "-o", "cyclonedx-json"],
                    capture_output=True,
                    text=True,
                    check=True
                )

                vulns_cyclonedx_json_data = json.loads(vulns_cyclonedx_json.stdout)

                previous_vulns_data = None
                
                if os.path.exists(vulns_output_path):
                    with open(vulns_output_path, "r") as f:
                        try:
                            previous_vulns_data = json.load(f)
                        except json.JSONDecodeError:
                            previous_vulns_data = None

                current_cve_ids = extract_cve_ids(vulns_cyclonedx_json_data)
                previous_cve_ids = extract_cve_ids(previous_vulns_data) if previous_vulns_data else set()

                new_cves = current_cve_ids - previous_cve_ids

                if new_cves:
                    message = f"[!] New vulnerabilities detected in repo {repo_name}: {', '.join(sorted(new_cves))}"
                    alert = "Scheduled Event : New Vulnerabilities Detected"
                    print(message)
                    alert_event_system(message, alert, alert_path)

                with open(vulns_output_path, "w") as f:
                    f.write(vulns_cyclonedx_json.stdout)

                prio_vuln_data = compare_kev_catalog(vulns_cyclonedx_json_data)
                with open(prio_output_path, "w") as f:
                    json.dump(prio_vuln_data, f, indent=4)

                print(f"[+] Scan finished for repo: {repo_name}")

            except subprocess.CalledProcessError as e:
                message = f"[!] Scan failed for {repo_name}: {e.stderr}"
                alert = "Scheduled Event : Scan Fail"
                timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
                print(f"{message}")
                alert_event_system(message, alert, alert_path)
                log_event(repo_path, repo_name, timestamp, message, scheduled_event_commit_sha, scheduled_event_commit_author)
                continue